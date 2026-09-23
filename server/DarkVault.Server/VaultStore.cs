using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

namespace DarkVault.Server;

public sealed partial class VaultStore : IDisposable {
    private readonly SqliteConnection db;
    private readonly string databasePath;
    private readonly KeyRing ring;
    // ponytail: single-instance serialized transactions; use a shared database before adding replicas.
    private readonly object gate = new();
    private DateTimeOffset lastAuditCleanup;
    // Set once at startup from Audit:RetentionDays, before requests are served.
    public TimeSpan AuditRetention { get; set; } = TimeSpan.FromDays(90);
    public static readonly string[] Scopes = ["secret:read", "secret:write", "secret:delete", "secret:list", "bucket:create", "bucket:read", "bucket:list", "bucket:delete", "bucket:write"];
    public VaultStore(string path, KeyRing ring) {
        this.ring = ring; databasePath = path;
        db = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()); db.Open();
        Execute("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS buckets (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS entries (id TEXT PRIMARY KEY, bucket TEXT NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
                name TEXT NOT NULL, json TEXT NOT NULL, keyid TEXT NOT NULL, nonce TEXT NOT NULL, value_json_bytes INTEGER NOT NULL DEFAULT -1,
                secret_pair_bytes INTEGER NOT NULL DEFAULT -1, type_pair_bytes INTEGER NOT NULL DEFAULT -1,
                UNIQUE(bucket,name), UNIQUE(keyid,nonce));
            CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS replay (principal TEXT NOT NULL, id TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(principal,id));
            CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, json TEXT NOT NULL, search TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT 'operation', result TEXT NOT NULL DEFAULT 'success');
            CREATE INDEX IF NOT EXISTS audit_time ON audit(time);
            INSERT OR IGNORE INTO settings VALUES ('revision','0');
            """);
        EnsureEntrySizeSchema();
        EnsureAuditSearchSchema();
        // Validate existing ciphertext before the instance accepts commands after recovery.
        Verify();
    }
    public void Dispose() => db.Dispose();
    private SqliteCommand Command(string sql, params object?[] values) {
        var cmd = db.CreateCommand(); cmd.CommandText = sql;
        for (var i = 0; i < values.Length; i++) cmd.Parameters.AddWithValue("$p" + i, values[i] ?? DBNull.Value);
        return cmd;
    }
    private void Execute(string sql, params object?[] values) { using var cmd = Command(sql, values); cmd.ExecuteNonQuery(); }
    private object? Scalar(string sql, params object?[] values) { using var cmd = Command(sql, values); return cmd.ExecuteScalar(); }
    private static SqliteCommand Command(SqliteConnection connection, string sql, params object?[] values) {
        var cmd = connection.CreateCommand(); cmd.CommandText = sql;
        for (var i = 0; i < values.Length; i++) cmd.Parameters.AddWithValue("$p" + i, values[i] ?? DBNull.Value);
        return cmd;
    }
    private T? One<T>(string sql, params object?[] values) => Scalar(sql, values) is string json ? ServerJson.Parse<T>(json) : default;
    private void VerifyAudit() {
        using var cmd = Command("SELECT json FROM audit"); using var reader = cmd.ExecuteReader();
        while (reader.Read()) _ = ServerJson.Parse<AuditEntry>(reader.GetString(0));
    }
    private List<T> Many<T>(string sql, params object?[] values) {
        using var cmd = Command(sql, values); using var reader = cmd.ExecuteReader(); var list = new List<T>();
        while (reader.Read()) list.Add(ServerJson.Parse<T>(reader.GetString(0))); return list;
    }
    private long Revision() {
        var value = long.Parse((string)Scalar("SELECT json FROM settings WHERE id='revision'")!, CultureInfo.InvariantCulture) + 1;
        if (value > 9007199254740991) throw new VaultFault(503, "revision_exhausted");
        Execute("UPDATE settings SET json=$p0 WHERE id='revision'", value.ToString(CultureInfo.InvariantCulture)); return value;
    }
    public Admin? Administrator { get { lock (gate) return One<Admin>("SELECT json FROM settings WHERE id='admin'"); } }
    public void SetPassword(string password, bool reset = false, RequestAudit? context = null) {
        if (password is null || password.Length is < 15 or > 128) throw new VaultFault(400, "invalid_password");
        lock (gate) {
            var old = Administrator;
            if (old is not null && !reset) throw new VaultFault(409, "already_initialized");
            var admin = new Admin(old?.Id ?? Guid.NewGuid().ToString(), "", Guid.NewGuid().ToString());
            admin = admin with { Hash = new PasswordHasher<Admin>().HashPassword(admin, password) };
            using var tx = db.BeginTransaction();
            Execute("INSERT OR REPLACE INTO settings VALUES ('admin',$p0)", ServerJson.Serialize(admin));
            AuditOperation(new(admin.Id, true), "admin.password", context?.TraceId ?? Guid.NewGuid().ToString(), "success",
                (null, null), new(null, null, null, null, null, []), context);
            tx.Commit();
        }
    }
    public Admin? Login(string password) {
        if (password is null || password.Length > 128) return null;
        Admin? admin;
        lock (gate) admin = Administrator;
        if (admin is null || new PasswordHasher<Admin>().VerifyHashedPassword(admin, admin.Hash, password) == PasswordVerificationResult.Failed) return null;
        lock (gate) {
            var current = Administrator;
            return current?.Id == admin.Id && current.Hash == admin.Hash ? admin : null;
        }
    }
    public Principal Authenticate(string token) {
        if (!Wire.IsToken(token)) throw new VaultFault(401, "unauthorized");
        lock (gate) {
            var record = One<TokenRecord>("SELECT json FROM tokens WHERE hash=$p0", Wire.HashToken(token));
            if (record is null || record.RevokedAt is not null) throw new VaultFault(401, "unauthorized");
            record = LimitTokenLifetime(record);
            if (record.Info.ExpiresAt <= DateTimeOffset.UtcNow) throw new VaultFault(401, "unauthorized");
            if (record.LastUsedAt is null || record.LastUsedAt < DateTimeOffset.UtcNow.AddMinutes(-1)) SaveToken(record with { LastUsedAt = DateTimeOffset.UtcNow });
            return new(record.Info.Id, false, record.Info);
        }
    }
    private void SaveToken(TokenRecord token) => Execute("UPDATE tokens SET json=$p0 WHERE id=$p1", ServerJson.Serialize(token), token.Info.Id);
    private static TokenRecord LimitTokenLifetime(TokenRecord token) {
        var maximum = token.CreatedAt.AddYears(1);
        return token.Info.ExpiresAt is null || token.Info.ExpiresAt > maximum ? token with { Info = token.Info with { ExpiresAt = maximum } } : token;
    }
    public void Reserve(Principal principal, VaultRequest request) {
        lock (gate) {
            Execute("DELETE FROM replay WHERE expires < $p0", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            try { Execute("INSERT INTO replay VALUES ($p0,$p1,$p2)", principal.Id, request.RequestId, request.IssuedAt.AddSeconds(90).ToUnixTimeSeconds()); } catch (SqliteException ex) when (ex.SqliteErrorCode == 19) { throw new VaultFault(409, "replay_detected"); }
        }
    }
    public object Run(Principal principal, string operation, JsonElement parameters, string requestId, CancellationToken cancellationToken = default, RequestAudit? context = null) {
        if (operation == "audit.list") return RunAuditList(principal, parameters, requestId, cancellationToken, context);
        lock (gate) {
            cancellationToken.ThrowIfCancellationRequested();
            if (!principal.IsAdmin) {
                var current = One<TokenRecord>("SELECT json FROM tokens WHERE id=$p0", principal.Id);
                if (current is null || current.RevokedAt is not null) throw new VaultFault(401, "unauthorized");
                current = LimitTokenLifetime(current);
                if (current.Info.ExpiresAt <= DateTimeOffset.UtcNow) throw new VaultFault(401, "unauthorized");
                principal = new(current.Info.Id, false, current.Info);
            }
            using var tx = db.BeginTransaction();
            var target = AuditTarget(operation, parameters);
            var details = AuditParameters(operation, parameters);
            try {
                var removed = new List<AuditResource>();
                var result = Dispatch(principal, operation, parameters, removed);
                var after = AuditTarget(operation, parameters);
                target = (target.BucketId ?? after.BucketId, target.SecretId ?? after.SecretId);
                cancellationToken.ThrowIfCancellationRequested();
                details = AuditResult(details, result, removed.ToArray());
                AuditOperation(principal, operation, requestId, "success", target, details, context); tx.Commit(); return result;
            } catch (Exception ex) {
                tx.Rollback();
                AuditOperation(principal, operation, requestId, ex is VaultFault fault ? fault.Code : "unavailable", target, AuditParameters(operation, parameters), context);
                throw;
            }
        }
    }
    private (string? BucketId, string? SecretId) AuditTarget(string operation, JsonElement parameters) {
        if (parameters.ValueKind != JsonValueKind.Object || (!operation.StartsWith("bucket.", StringComparison.Ordinal) && !operation.StartsWith("secret.", StringComparison.Ordinal))) return (null, null);
        var name = parameters.TryGetProperty(operation == "bucket.create" ? "name" : "bucket", out var b) ? b : default;
        if (name.ValueKind != JsonValueKind.String) return (null, null);
        var id = Scalar("SELECT id FROM buckets WHERE name=$p0", name.GetString()) as string;
        var secretId = id is not null && parameters.TryGetProperty("key", out var k) && k.ValueKind == JsonValueKind.String
            ? Scalar("SELECT id FROM entries WHERE bucket=$p0 AND name=$p1", id, k.GetString()) as string : null;
        return (id, secretId);
    }
    private void EnsureEntrySizeSchema() {
        foreach (var (name, definition) in new[] {
            ("value_json_bytes", "value_json_bytes INTEGER NOT NULL DEFAULT -1"),
            ("secret_pair_bytes", "secret_pair_bytes INTEGER NOT NULL DEFAULT -1"),
            ("type_pair_bytes", "type_pair_bytes INTEGER NOT NULL DEFAULT -1")
        }) {
            try { using var command = Command("SELECT " + name + " FROM entries LIMIT 1"); command.ExecuteScalar(); } catch (SqliteException) { Execute("ALTER TABLE entries ADD COLUMN " + definition); }
        }
    }
    private void EnsureAuditSearchSchema() {
        try { using var command = Command("SELECT search FROM audit LIMIT 1"); command.ExecuteScalar(); } catch (SqliteException) { Execute("ALTER TABLE audit ADD COLUMN search TEXT NOT NULL DEFAULT ''"); }
        Execute("CREATE INDEX IF NOT EXISTS audit_search_id ON audit(search,id)");
        try { using var command = Command("SELECT kind,result FROM audit LIMIT 1"); command.ExecuteScalar(); } catch (SqliteException) {
            Execute("ALTER TABLE audit ADD COLUMN kind TEXT NOT NULL DEFAULT 'operation'");
            Execute("ALTER TABLE audit ADD COLUMN result TEXT NOT NULL DEFAULT 'success'");
            Execute("UPDATE audit SET kind=coalesce(json_extract(json,'$.kind'),'operation'), result=coalesce(json_extract(json,'$.result'),'success')");
        }
        Execute("CREATE INDEX IF NOT EXISTS audit_kind_id ON audit(kind,id)");
        Execute("CREATE INDEX IF NOT EXISTS audit_result_id ON audit(result,id)");
        if (Scalar("SELECT 1 FROM audit WHERE search = '' LIMIT 1") is not null) Execute("UPDATE audit SET search = trim(coalesce(json_extract(json,'$.operation'),'') || ' ' || coalesce(json_extract(json,'$.principal'),'') || ' ' || coalesce(json_extract(json,'$.principalName'),'') || ' ' || coalesce(json_extract(json,'$.sourceIp'),'') || ' ' || coalesce(json_extract(json,'$.path'),'') || ' ' || coalesce(json_extract(json,'$.requestId'),'') || ' ' || coalesce(json_extract(json,'$.traceId'),'') || ' ' || coalesce(json_extract(json,'$.details'),'') || ' ' || coalesce(json_extract(json,'$.bucketId'),'') || ' ' || coalesce(json_extract(json,'$.secretId'),'')) WHERE search = ''");
    }
    private static string AuditSearch(AuditEntry entry) {
        var values = new List<string?> {
            entry.Operation, entry.Principal, entry.Result, entry.Kind, entry.PrincipalType, entry.PrincipalName,
            entry.SourceIp, entry.PeerIp, entry.Method, entry.Path, entry.RequestId, entry.TraceId, entry.BucketId, entry.SecretId,
            entry.StatusCode?.ToString(CultureInfo.InvariantCulture), entry.DurationMs?.ToString(CultureInfo.InvariantCulture)
        };
        if (entry.Details is { } details) {
            values.AddRange([details.Bucket, details.Key, details.TokenId,
                details.ExpectedRevision?.ToString(CultureInfo.InvariantCulture), details.Recursive?.ToString(), details.ReturnedCount?.ToString(CultureInfo.InvariantCulture)]);
            values.AddRange(details.Resources.SelectMany(resource => new[] {
                resource.Kind, resource.Id, resource.Name, resource.BucketId, resource.Type,
                resource.Revision?.ToString(CultureInfo.InvariantCulture)
            }));
            if (details.Token is { } token) values.AddRange([token.Id, token.Name, token.AllBuckets.ToString(), token.ExpiresAt?.ToString("O"), .. token.Scopes, .. token.BucketIds, .. token.CreatableBucketNames]);
        }
        return string.Join(' ', values.Where(value => !string.IsNullOrWhiteSpace(value)));
    }
    private void Audit(AuditEntry entry) {
        // ponytail: hourly retention maintenance; avoid a DELETE write on every audit event.
        if (lastAuditCleanup == default || entry.Time - lastAuditCleanup >= TimeSpan.FromHours(1)) {
            Execute("DELETE FROM audit WHERE time < $p0", (entry.Time - AuditRetention).ToString("O"));
            // A token ends at the earliest of revocation, expiry and the one-year lifetime cap; drop records
            // a year past that point. Their audit events keep the token id and name.
            Execute("""
                DELETE FROM tokens WHERE min(coalesce(julianday(json_extract(json,'$.revokedAt')), 1e9),
                    coalesce(julianday(json_extract(json,'$.info.expiresAt')), 1e9),
                    julianday(json_extract(json,'$.createdAt'), '+1 year')) < julianday($p0)
                """, entry.Time.AddDays(-365).ToString("O"));
            lastAuditCleanup = entry.Time;
        }
        void Insert(AuditEntry value) => Execute("INSERT INTO audit(time,json,search,kind,result) VALUES ($p0,$p1,$p2,$p3,$p4)", value.Time.ToString("O"), ServerJson.Serialize(value), AuditSearch(value), value.Kind, value.Result);
        if (entry.Details is { Resources.Length: > 200 } details) {
            foreach (var chunk in details.Resources.Chunk(200)) Insert(entry with { Details = details with { Resources = chunk } });
        } else Insert(entry);
    }
    private void AuditOperation(Principal principal, string operation, string requestId, string result,
        (string? BucketId, string? SecretId) target, AuditDetails details, RequestAudit? context) =>
        Audit(new(DateTimeOffset.UtcNow, principal.Id, operation, target.BucketId, target.SecretId, requestId, result,
            PrincipalType: principal.IsAdmin ? "admin" : "token", PrincipalName: principal.IsAdmin ? "admin" : principal.Token?.Name,
            TraceId: context?.TraceId, StartedAt: context?.StartedAt, SourceIp: context?.SourceIp, PeerIp: context?.PeerIp,
            Method: context?.Method, Path: context?.Path, DurationMs: context?.DurationMs, Details: details));
    internal void RecordRequest(AuditEntry entry) { lock (gate) Audit(entry); }
    internal static AuditDetails AuditParameters(string operation, JsonElement parameters) {
        string? TextField(string name, int max) => parameters.ValueKind == JsonValueKind.Object && parameters.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String && value.GetString() is { } text && text.Length <= max ? text : null;
        long? revision = parameters.ValueKind == JsonValueKind.Object && parameters.TryGetProperty("expectedRevision", out var r)
            && r.ValueKind == JsonValueKind.Number && r.TryGetInt64(out var number) ? number : null;
        bool? recursive = parameters.ValueKind == JsonValueKind.Object && parameters.TryGetProperty("recursive", out var b)
            && b.ValueKind is JsonValueKind.True or JsonValueKind.False ? b.GetBoolean() : null;
        return new(operation == "bucket.create" ? TextField("name", 63) : TextField("bucket", 63),
            TextField("key", 255), operation == "token.revoke" ? TextField("id", 255) : null, revision, recursive, []);
    }
    private static AuditResource Resource(SecretMetadata secret) => new("secret", secret.Id, secret.Key, secret.BucketId, secret.Revision, secret.Type);
    private static AuditResource Resource(Bucket bucket) => new("bucket", bucket.Id, bucket.Name, Revision: bucket.Revision);
    private AuditDetails AuditResult(AuditDetails details, object result, AuditResource[] removed) {
        var resources = result switch {
            Bucket b => [Resource(b)],
            SecretMetadata s => [Resource(s)],
            Secret s => [new AuditResource("secret", s.Id, s.Key, s.BucketId, s.Revision, s.Type)],
            BucketSnapshot b => Many<StoredSecret>("SELECT json FROM entries WHERE bucket=$p0", b.BucketId).Select(s => Resource(s.Metadata.ToContract())).ToArray(),
            Page<Bucket> page => page.Items.Select(Resource).ToArray(),
            Page<SecretMetadata> page => page.Items.Select(Resource).ToArray(),
            TokenCreated t => [new AuditResource("token", t.Metadata.Info.Id, t.Metadata.Info.Name)],
            TokenInfo t => [new AuditResource("token", t.Id, t.Name)],
            Page<TokenRecord> page => page.Items.Select(t => new AuditResource("token", t.Info.Id, t.Info.Name)).ToArray(),
            RevokeResult when details.TokenId is not null => [new AuditResource("token", details.TokenId,
                One<TokenRecord>("SELECT json FROM tokens WHERE id=$p0", details.TokenId)!.Info.Name)],
            _ => removed
        };
        return details with {
            Resources = resources,
            ReturnedCount = result is Page<JsonElement> audit ? audit.Items.Count : resources.Length,
            Token = result is TokenCreated created ? created.Metadata.Info : result is TokenInfo info ? StoredTokenInfo.FromContract(info) : null
        };
    }
    private static void Require(Principal p, params string[] scopes) {
        if (!p.IsAdmin && scopes.Any(s => !p.Token!.Scopes.Contains(s))) throw new VaultFault(403, "forbidden");
    }
    private static bool Allowed(Principal p, string id) => p.IsAdmin || p.Token!.AllBuckets || p.Token.BucketIds.Contains(id);
    private static void Fields(JsonElement p, params string[] fields) {
        if (p.ValueKind != JsonValueKind.Object || p.EnumerateObject().Any(f => !fields.Contains(f.Name))) throw new VaultFault(400, "invalid_request");
    }
    private static string Text(JsonElement p, string field, int max = 255, bool optional = false) {
        if (!p.TryGetProperty(field, out var v)) { if (optional) return ""; throw new VaultFault(400, "invalid_request"); }
        if (v.ValueKind != JsonValueKind.String) throw new VaultFault(400, "invalid_request");
        var value = v.GetString()!;
        if (Encoding.UTF8.GetByteCount(value) > max || (!optional && value.Length == 0)) throw new VaultFault(400, "invalid_request");
        return value;
    }
    private static long Expected(JsonElement p) {
        if (!p.TryGetProperty("expectedRevision", out var v) || v.ValueKind != JsonValueKind.Number || !v.TryGetInt64(out var n) || n < 0 || n > 9007199254740991) throw new VaultFault(400, "invalid_request");
        return n;
    }
    private static bool Boolean(JsonElement p, string name) => p.TryGetProperty(name, out var b) ? b.ValueKind switch {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        _ => throw new VaultFault(400, "invalid_request")
    } : false;
    public static void ValidateName(string name) { if (!Regex.IsMatch(name, @"\A[a-z0-9][a-z0-9_-]{0,62}\z", RegexOptions.CultureInvariant)) throw new VaultFault(400, "invalid_bucket_name"); }
    private static void Match(long expected, long actual) { if (expected != actual) throw new VaultFault(409, "revision_conflict"); }
    private static (string Cursor, int Limit) Paging(JsonElement p) {
        var limit = 100;
        if (p.TryGetProperty("limit", out var l) && (l.ValueKind != JsonValueKind.Number || !l.TryGetInt32(out limit))) throw new VaultFault(400, "invalid_request");
        if (limit is < 1 or > 200) throw new VaultFault(400, "invalid_request");
        var cursor = "";
        if (p.TryGetProperty("cursor", out var c) && c.ValueKind != JsonValueKind.Null) {
            try { cursor = Encoding.UTF8.GetString(Wire.Unbase64(c.GetString()!)); } catch { throw new VaultFault(400, "invalid_cursor"); }
        }
        return (cursor, limit);
    }
    private static Page<T> PageRows<T>(IReadOnlyList<T> rows, Func<T, string> id, int limit) {
        var items = rows.Take(limit).ToArray();
        return new Page<T>(items, rows.Count > limit ? Wire.Base64(Encoding.UTF8.GetBytes(id(items[^1]))) : null);
    }
    private Page<Bucket> ListBuckets(Principal principal, JsonElement parameters) {
        var (cursor, limit) = Paging(parameters);
        var sql = "SELECT json FROM buckets WHERE id > $p0";
        object?[] values;
        if (principal.IsAdmin || principal.Token!.AllBuckets) {
            sql += " ORDER BY id LIMIT $p1";
            values = [cursor, limit + 1];
        } else {
            var ids = principal.Token.BucketIds;
            if (ids.Length == 0) return new Page<Bucket>(Array.Empty<Bucket>(), null);
            var placeholders = string.Join(",", Enumerable.Range(0, ids.Length).Select(i => "$p" + (i + 2)));
            sql += $" AND id IN ({placeholders}) ORDER BY id LIMIT $p1";
            values = new object?[ids.Length + 2]; values[0] = cursor; values[1] = limit + 1; Array.Copy(ids, 0, values, 2, ids.Length);
        }
        return PageRows(Many<StoredBucket>(sql, values).Select(b => b.ToContract()).ToArray(), b => b.Id, limit);
    }
    private Page<SecretMetadata> ListSecrets(Bucket bucket, JsonElement parameters) {
        var (cursor, limit) = Paging(parameters);
        var rows = Many<StoredSecret>("SELECT json FROM entries WHERE bucket=$p0 AND id>$p1 ORDER BY id LIMIT $p2", bucket.Id, cursor, limit + 1)
            .Select(s => s.Metadata.ToContract()).ToArray();
        return PageRows(rows, m => m.Id, limit);
    }
    private Page<TokenRecord> ListTokens(JsonElement parameters) {
        var (cursor, limit) = Paging(parameters);
        var rows = Many<TokenRecord>("SELECT json FROM tokens WHERE id>$p0 ORDER BY id LIMIT $p1", cursor, limit + 1)
            .Select(LimitTokenLifetime).ToArray();
        return PageRows(rows, t => t.Info.Id, limit);
    }
    private object Dispatch(Principal p, string op, JsonElement args, List<AuditResource> removed) {
        if (op == "token.info") { Fields(args); if (p.IsAdmin) throw new VaultFault(400, "invalid_request"); return p.Token!.ToContract(); }
        if (op.StartsWith("token.", StringComparison.Ordinal) || op == "audit.list") return AdminCommand(p, op, args);
        if (op == "bucket.list") {
            Fields(args, "cursor", "limit"); Require(p, "bucket:list");
            return ListBuckets(p, args);
        }
        if (op == "bucket.create") {
            Fields(args, "name", "description"); Require(p, "bucket:create");
            var name = Text(args, "name", 63); ValidateName(name);
            if (!p.IsAdmin && !p.Token!.AllBuckets && !p.Token.CreatableBucketNames.Contains(name)) throw new VaultFault(403, "forbidden");
            if (Scalar("SELECT id FROM buckets WHERE name=$p0", name) is not null) throw new VaultFault(409, "already_exists");
            var now = DateTimeOffset.UtcNow;
            var b = new Bucket(Guid.NewGuid().ToString(), name, Text(args, "description", 1024, true), Revision(), now, now);
            Execute("INSERT INTO buckets VALUES ($p0,$p1,$p2)", b.Id, b.Name, ServerJson.Serialize(StoredBucket.FromContract(b)));
            if (!p.IsAdmin && !p.Token!.AllBuckets) {
                var token = One<TokenRecord>("SELECT json FROM tokens WHERE id=$p0", p.Id)!;
                SaveToken(token with { Info = token.Info with { BucketIds = [.. token.Info.BucketIds, b.Id], CreatableBucketNames = token.Info.CreatableBucketNames.Where(n => n != name).ToArray() } });
            }
            return b;
        }
        var bucketName = Text(args, "bucket", 63); ValidateName(bucketName);
        var bucket = One<StoredBucket>("SELECT json FROM buckets WHERE name=$p0", bucketName)?.ToContract();
        if (bucket is null || !Allowed(p, bucket.Id)) throw new VaultFault(404, "not_found");
        if (op == "bucket.get") { Fields(args, "bucket"); Require(p, "bucket:read"); return bucket; }
        if (op == "bucket.read") {
            Fields(args, "bucket"); Require(p, "bucket:read", "secret:read", "secret:list");
            var snapshot = Entries(bucket.Id);
            return new BucketSnapshot(bucket.Id, bucket.Revision, Values(snapshot), Types(snapshot));
        }
        if (op == "bucket.update") {
            var hasName = args.TryGetProperty("name", out _);
            var hasDescription = args.TryGetProperty("description", out _);
            if (!hasName && !hasDescription) throw new VaultFault(400, "invalid_request");
            Fields(args, "bucket", "name", "description", "expectedRevision"); Require(p, "bucket:write"); Match(Expected(args), bucket.Revision);
            var name = hasName ? Text(args, "name", 63) : bucket.Name; ValidateName(name);
            if (name != bucket.Name && Scalar("SELECT id FROM buckets WHERE name=$p0", name) is not null) throw new VaultFault(409, "already_exists");
            bucket = bucket with { Name = name, Description = hasDescription ? Text(args, "description", 1024, true) : bucket.Description, Revision = Revision(), UpdatedAt = DateTimeOffset.UtcNow };
            SaveBucket(bucket); return bucket;
        }
        if (op == "bucket.delete") {
            Fields(args, "bucket", "expectedRevision", "recursive"); Require(p, "bucket:delete"); Match(Expected(args), bucket.Revision);
            var recursive = Boolean(args, "recursive");
            if (recursive) Require(p, "secret:delete");
            if (!recursive && (long)Scalar("SELECT count(*) FROM entries WHERE bucket=$p0", bucket.Id)! > 0) throw new VaultFault(409, "bucket_not_empty");
            removed.Add(Resource(bucket));
            removed.AddRange(Many<StoredSecret>("SELECT json FROM entries WHERE bucket=$p0", bucket.Id).Select(s => Resource(s.Metadata.ToContract())));
            Execute("DELETE FROM buckets WHERE id=$p0", bucket.Id); Revision(); return new DeleteResult(true);
        }
        if (op == "secret.list") {
            Fields(args, "bucket", "cursor", "limit"); Require(p, "secret:list");
            return ListSecrets(bucket, args);
        }
        var key = Text(args, "key");
        if (key.Any(char.IsControl)) throw new VaultFault(400, "invalid_key");
        var old = One<StoredSecret>("SELECT json FROM entries WHERE bucket=$p0 AND name=$p1", bucket.Id, key);
        if (op == "secret.read") {
            Fields(args, "bucket", "key"); Require(p, "secret:read");
            if (old is null) throw new VaultFault(404, "not_found");
            var m = old.Metadata.ToContract(); return new Secret(m.Id, m.BucketId, m.Key, m.Revision, m.CreatedAt, m.UpdatedAt, ring.Decrypt(old.Value, m), m.Type);
        }
        if (op == "secret.delete") {
            Fields(args, "bucket", "key", "expectedRevision"); Require(p, "secret:delete");
            if (old is null) throw new VaultFault(404, "not_found"); Match(Expected(args), old.Metadata.Revision);
            removed.Add(Resource(old.Metadata.ToContract()));
            Execute("DELETE FROM entries WHERE id=$p0", old.Metadata.Id);
            SaveBucket(bucket with { Revision = Revision(), UpdatedAt = DateTimeOffset.UtcNow }); return new DeleteResult(true);
        }
        if (op is not ("secret.create" or "secret.update" or "secret.set")) throw new VaultFault(400, "unknown_operation");
        Fields(args, op == "secret.create" ? ["bucket", "key", "value", "type"] : ["bucket", "key", "value", "type", "expectedRevision"]);
        Require(p, "secret:write");
        if (op == "secret.create" && old is not null) throw new VaultFault(409, "already_exists");
        if (op == "secret.update" && old is null) throw new VaultFault(404, "not_found");
        if (op != "secret.create") Match(Expected(args), old?.Metadata.Revision ?? 0);
        if (!args.TryGetProperty("value", out var input) || input.ValueKind != JsonValueKind.String) throw new VaultFault(400, "invalid_request");
        var value = input.GetString()!;
        if (Encoding.UTF8.GetByteCount(value) > 65536) throw new VaultFault(413, "payload_too_large");
        var type = args.TryGetProperty("type", out _) ? Text(args, "type", 16) : old?.Metadata.Type ?? "string";
        try { value = SecretValues.Normalize(value, type); } catch (ArgumentException) { throw new VaultFault(400, "invalid_secret_type"); }
        var entryCount = (long)Scalar("SELECT count(*) FROM entries WHERE bucket=$p0", bucket.Id)! + (old is null ? 1 : 0);
        if (entryCount > 4096) throw new VaultFault(413, "payload_too_large");
        var time = DateTimeOffset.UtcNow;
        var revision = Revision();
        if (SnapshotBytes(bucket.Id, revision, old?.Metadata.Id, key, type, value) > 1024 * 1024) throw new VaultFault(413, "payload_too_large");
        var meta = new SecretMetadata(old?.Metadata.Id ?? Guid.NewGuid().ToString(), bucket.Id, key, revision, old?.Metadata.CreatedAt ?? time, time, type);
        SaveSecret(meta, value);
        SaveBucket(bucket with { Revision = revision, UpdatedAt = time }); return meta;
    }
    private void SaveSecret(SecretMetadata meta, string value) {
        for (var attempt = 0; attempt < 3; attempt++) {
            var secret = new StoredSecret(StoredSecretMetadata.FromContract(meta), ring.Encrypt(value, meta));
            try {
                var valueJsonBytes = JsonStringBytes(value); var keyJsonBytes = JsonStringBytes(meta.Key);
                var secretPairBytes = keyJsonBytes + 1 + valueJsonBytes;
                var typePairBytes = meta.Type == "string" ? 0 : keyJsonBytes + 1 + JsonStringBytes(meta.Type);
                Execute("INSERT INTO entries(id,bucket,name,json,keyid,nonce,value_json_bytes,secret_pair_bytes,type_pair_bytes) VALUES ($p0,$p1,$p2,$p3,$p4,$p5,$p6,$p7,$p8) ON CONFLICT(id) DO UPDATE SET json=$p3,keyid=$p4,nonce=$p5,value_json_bytes=$p6,secret_pair_bytes=$p7,type_pair_bytes=$p8",
                    meta.Id, meta.BucketId, meta.Key, ServerJson.Serialize(secret), secret.Value.KeyId, secret.Value.Nonce,
                    valueJsonBytes, secretPairBytes, typePairBytes);
                return;
            } catch (SqliteException ex) when (ex.SqliteErrorCode == 19 &&
                (long)Scalar("SELECT count(*) FROM entries WHERE keyid=$p0 AND nonce=$p1", secret.Value.KeyId, secret.Value.Nonce)! > 0) { }
        }
        throw new CryptographicException("Unable to allocate a unique nonce.");
    }
    private void SaveBucket(Bucket b) => Execute("UPDATE buckets SET json=$p0, name=$p2 WHERE id=$p1", ServerJson.Serialize(StoredBucket.FromContract(b)), b.Id, b.Name);
    private static int JsonStringBytes(string value) => Encoding.UTF8.GetByteCount(ServerJson.Serialize(value));
    private void BackfillEntrySizes(string bucket) {
        var rows = new List<StoredSecret>();
        using (var command = Command("SELECT json FROM entries WHERE bucket=$p0 AND (value_json_bytes<0 OR secret_pair_bytes<0 OR type_pair_bytes<0)", bucket))
        using (var reader = command.ExecuteReader()) while (reader.Read()) rows.Add(ServerJson.Parse<StoredSecret>(reader.GetString(0)));
        foreach (var stored in rows) {
            var plaintext = ring.Decrypt(stored.Value, stored.Metadata.ToContract());
            var valueBytes = JsonStringBytes(plaintext); var keyBytes = JsonStringBytes(stored.Metadata.Key);
            var secretPairBytes = keyBytes + 1 + valueBytes;
            var typePairBytes = stored.Metadata.Type == "string" ? 0 : keyBytes + 1 + JsonStringBytes(stored.Metadata.Type);
            Execute("UPDATE entries SET value_json_bytes=$p0,secret_pair_bytes=$p1,type_pair_bytes=$p2 WHERE id=$p3",
                valueBytes, secretPairBytes, typePairBytes, stored.Metadata.Id);
        }
    }
    private int SnapshotBytes(string bucketId, long revision, string? replacedId, string key, string type, string value) {
        BackfillEntrySizes(bucketId);
        var count = (long)Scalar("SELECT count(*) FROM entries WHERE bucket=$p0", bucketId)!;
        var secretBytes = (long)Scalar("SELECT coalesce(sum(secret_pair_bytes),0) FROM entries WHERE bucket=$p0", bucketId)!;
        var typeBytes = (long)Scalar("SELECT coalesce(sum(type_pair_bytes),0) FROM entries WHERE bucket=$p0", bucketId)!;
        var typeCount = (long)Scalar("SELECT count(*) FROM entries WHERE bucket=$p0 AND type_pair_bytes>0", bucketId)!;
        if (replacedId is not null) {
            secretBytes -= (long)Scalar("SELECT secret_pair_bytes FROM entries WHERE id=$p0", replacedId)!;
            var oldTypeBytes = (long)Scalar("SELECT type_pair_bytes FROM entries WHERE id=$p0", replacedId)!;
            typeBytes -= oldTypeBytes;
            if (oldTypeBytes > 0) typeCount--;
        } else count++;
        var keyBytes = JsonStringBytes(key); var valueBytes = JsonStringBytes(value);
        secretBytes += keyBytes + 1 + valueBytes;
        if (type != "string") { typeBytes += keyBytes + 1 + JsonStringBytes(type); typeCount++; }
        var snapshot = new BucketSnapshot(bucketId, revision, new Dictionary<string, string?>(), new Dictionary<string, string>());
        var total = (long)Encoding.UTF8.GetByteCount(ServerJson.Serialize(snapshot));
        if (count > 0) total += secretBytes + count - 3;
        if (typeCount > 0) total += typeBytes + typeCount - 3;
        return checked((int)total);
    }
    private List<StoredSecret> Entries(string bucket) => Many<StoredSecret>("SELECT json FROM entries WHERE bucket=$p0", bucket);
    private Dictionary<string, string?> Values(List<StoredSecret> entries) =>
        entries.ToDictionary(s => s.Metadata.Key, s => (string?)ring.Decrypt(s.Value, s.Metadata.ToContract()), StringComparer.Ordinal);
    private static Dictionary<string, string> Types(List<StoredSecret> entries) =>
        entries.Where(s => s.Metadata.Type != "string").ToDictionary(s => s.Metadata.Key, s => s.Metadata.Type, StringComparer.Ordinal);
    private object RunAuditList(Principal principal, JsonElement parameters, string requestId, CancellationToken cancellationToken, RequestAudit? context) {
        var target = AuditTarget("audit.list", parameters); var details = AuditParameters("audit.list", parameters); object result;
        try {
            cancellationToken.ThrowIfCancellationRequested();
            if (!principal.IsAdmin) throw new VaultFault(403, "forbidden");
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false, Mode = SqliteOpenMode.ReadOnly }.ToString());
            connection.Open(); result = ListAudit(parameters, connection);
            cancellationToken.ThrowIfCancellationRequested();
            details = AuditResult(details, result, []);
        } catch (Exception ex) {
            RecordAuditList(principal, requestId, ex is VaultFault fault ? fault.Code : "unavailable", target, details, context);
            throw;
        }
        RecordAuditList(principal, requestId, "success", target, details, context);
        return result;
    }
    private void RecordAuditList(Principal principal, string requestId, string result, (string? BucketId, string? SecretId) target, AuditDetails details, RequestAudit? context) {
        lock (gate) { using var tx = db.BeginTransaction(); AuditOperation(principal, "audit.list", requestId, result, target, details, context); tx.Commit(); }
    }
    private Page<JsonElement> ListAudit(JsonElement args, SqliteConnection connection) {
        Fields(args, "cursor", "limit", "order", "search", "kind", "result"); var (cursor, limit) = Paging(args);
        var order = Text(args, "order", 4, true); var kind = Text(args, "kind", 16, true); var result = Text(args, "result", 16, true);
        if (order is not ("" or "asc" or "desc") || kind is not ("" or "http" or "operation") || result is not ("" or "success" or "failure")) throw new VaultFault(400, "invalid_request");
        var descending = order == "desc";
        if (cursor == "") cursor = descending ? long.MaxValue.ToString(CultureInfo.InvariantCulture) : "0";
        if (!long.TryParse(cursor, out var after) || after < 0) throw new VaultFault(400, "invalid_cursor");
        var search = Text(args, "search", 1024, true);
        if (search.Length > 256) throw new VaultFault(400, "invalid_request");
        var pattern = "%" + search.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_") + "%";
        var kindFilter = kind == "" ? "" : "AND kind = $p2";
        var resultFilter = result switch { "success" => "AND result = 'success'", "failure" => "AND result != 'success'", _ => "" };
        using var cmd = Command(connection, $"""
            SELECT id,json FROM audit WHERE id {(descending ? "<" : ">")} $p0
            {kindFilter}
            {resultFilter}
            AND ($p4 = '' OR search LIKE $p5 ESCAPE '\')
            ORDER BY id {(descending ? "DESC" : "ASC")} LIMIT $p1
            """, after, limit + 1, kind, result, search, pattern);
        using var reader = cmd.ExecuteReader(); var items = new List<JsonElement>(); long last = after; var bytes = 0; var more = false;
        while (reader.Read()) {
            var json = reader.GetString(1); var size = Encoding.UTF8.GetByteCount(json);
            if (items.Count == limit || (items.Count > 0 && bytes + size > Wire.MaxPlaintext - 4096)) { more = true; break; }
            last = reader.GetInt64(0); items.Add(ServerJson.Parse<JsonElement>(json)); bytes += size + 1;
        }
        return new Page<JsonElement>(items.ToArray(), more ? Wire.Base64(Encoding.UTF8.GetBytes(last.ToString(CultureInfo.InvariantCulture))) : null);
    }
    private object AdminCommand(Principal p, string op, JsonElement args) {
        if (!p.IsAdmin) throw new VaultFault(403, "forbidden");
        if (op == "token.create") {
            Fields(args, "name", "scopes", "bucketIds", "allBuckets", "creatableBucketNames", "expiresAt");
            var name = Text(args, "name", 128);
            string[] Strings(string field) {
                if (!args.TryGetProperty(field, out var a) || a.ValueKind != JsonValueKind.Array || a.GetArrayLength() > 200) throw new VaultFault(400, "invalid_request");
                return a.EnumerateArray().Select(v => v.ValueKind == JsonValueKind.String ? v.GetString()! : throw new VaultFault(400, "invalid_request")).Distinct().ToArray();
            }
            var scopes = Strings("scopes"); var buckets = Strings("bucketIds"); var names = Strings("creatableBucketNames");
            if (scopes.Any(s => !Scopes.Contains(s)) || buckets.Any(b => Scalar("SELECT id FROM buckets WHERE id=$p0", b) is null)) throw new VaultFault(400, "invalid_request");
            foreach (var n in names) ValidateName(n);
            var all = Boolean(args, "allBuckets");
            if (names.Length > 0 && !scopes.Contains("bucket:create")) throw new VaultFault(400, "invalid_request");
            DateTimeOffset? expiry = DateTimeOffset.UtcNow.AddDays(30);
            if (args.TryGetProperty("expiresAt", out var e)) {
                if (e.ValueKind == JsonValueKind.Null) expiry = DateTimeOffset.UtcNow.AddDays(30);
                else if (e.ValueKind == JsonValueKind.String && e.TryGetDateTimeOffset(out var dt) && dt.Offset == TimeSpan.Zero) expiry = dt;
                else throw new VaultFault(400, "invalid_request");
            }
            if (expiry <= DateTimeOffset.UtcNow || expiry > DateTimeOffset.UtcNow.AddYears(1)) throw new VaultFault(400, "invalid_request");
            var token = Wire.NewToken();
            var info = new StoredTokenInfo(Guid.NewGuid().ToString(), name, scopes, buckets, all, names, expiry);
            var record = new TokenRecord(info, DateTimeOffset.UtcNow, null, null);
            Execute("INSERT INTO tokens VALUES ($p0,$p1,$p2)", info.Id, Wire.HashToken(token), ServerJson.Serialize(record));
            return new TokenCreated(record, token);
        }
        if (op == "token.list") { Fields(args, "cursor", "limit"); return ListTokens(args); }
        if (op == "token.revoke") {
            Fields(args, "id"); var id = Text(args, "id");
            var token = One<TokenRecord>("SELECT json FROM tokens WHERE id=$p0", id) ?? throw new VaultFault(404, "not_found");
            SaveToken(token with { RevokedAt = token.RevokedAt ?? DateTimeOffset.UtcNow }); return new RevokeResult(true);
        }
        if (op == "audit.list") return ListAudit(args, db);
        throw new VaultFault(400, "unknown_operation");
    }
    public void Reencrypt() {
        lock (gate) {
            ring.RotateData();
            foreach (var stored in Many<StoredSecret>("SELECT json FROM entries")) {
                using var tx = db.BeginTransaction();
                SaveSecret(stored.Metadata.ToContract(), ring.Decrypt(stored.Value, stored.Metadata.ToContract()));
                tx.Commit();
            }
            ring.PruneUnusedDataKeys();
        }
    }
    public void Verify() {
        lock (gate) {
            if (!long.TryParse((string?)Scalar("SELECT json FROM settings WHERE id='revision'"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var revision) || revision < 0) throw new CryptographicException("Invalid revision state.");
            _ = Administrator; _ = Mfa;
            foreach (var bucket in Many<StoredBucket>("SELECT json FROM buckets")) ValidateName(bucket.Name);
            foreach (var secret in Many<StoredSecret>("SELECT json FROM entries")) _ = ring.Decrypt(secret.Value, secret.Metadata.ToContract());
            _ = Many<TokenRecord>("SELECT json FROM tokens");
            VerifyAudit();
            _ = ring.Public();
        }
    }
    public void Ready() { lock (gate) { _ = Scalar("SELECT 1"); _ = ring.Public(); } }
    public void Backup(string destination) { lock (gate) { if (File.Exists(destination)) throw new IOException("Backup destination exists."); using var target = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = destination, Pooling = false }.ToString()); target.Open(); db.BackupDatabase(target); } }
    public sealed record Admin(string Id, string Hash, string Stamp);
    public sealed record Principal(string Id, bool IsAdmin, StoredTokenInfo? Token = null);
    public sealed record TokenRecord(StoredTokenInfo Info, DateTimeOffset CreatedAt, DateTimeOffset? RevokedAt, DateTimeOffset? LastUsedAt);
    internal sealed record StoredSecret(StoredSecretMetadata Metadata, EncryptedValue Value);
}
