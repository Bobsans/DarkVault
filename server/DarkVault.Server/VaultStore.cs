using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DarkVault.Client;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;

namespace DarkVault.Server;

public sealed class VaultStore : IDisposable {
    private readonly SqliteConnection db;
    private readonly KeyRing ring;
    // ponytail: single-instance serialized transactions; use a shared database before adding replicas.
    private readonly object gate = new();
    public static readonly string[] Scopes = ["secret:read", "secret:write", "secret:delete", "secret:list", "bucket:create", "bucket:read", "bucket:list", "bucket:delete", "bucket:write"];
    public VaultStore(string path, KeyRing ring) {
        this.ring = ring;
        db = new(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()); db.Open();
        Execute("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS settings (id TEXT PRIMARY KEY, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS buckets (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS entries (id TEXT PRIMARY KEY, bucket TEXT NOT NULL REFERENCES buckets(id) ON DELETE CASCADE,
                name TEXT NOT NULL, json TEXT NOT NULL, keyid TEXT NOT NULL, nonce TEXT NOT NULL, UNIQUE(bucket,name), UNIQUE(keyid,nonce));
            CREATE TABLE IF NOT EXISTS tokens (id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL, json TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS replay (principal TEXT NOT NULL, id TEXT NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(principal,id));
            CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT NOT NULL, json TEXT NOT NULL);
            INSERT OR IGNORE INTO settings VALUES ('revision','0');
            """);
    }
    public void Dispose() => db.Dispose();
    private SqliteCommand Command(string sql, params object?[] values) {
        var cmd = db.CreateCommand(); cmd.CommandText = sql;
        for (var i = 0; i < values.Length; i++) cmd.Parameters.AddWithValue("$p" + i, values[i] ?? DBNull.Value);
        return cmd;
    }
    private void Execute(string sql, params object?[] values) { using var cmd = Command(sql, values); cmd.ExecuteNonQuery(); }
    private object? Scalar(string sql, params object?[] values) { using var cmd = Command(sql, values); return cmd.ExecuteScalar(); }
    private T? One<T>(string sql, params object?[] values) => Scalar(sql, values) is string json ? Wire.Parse<T>(json) : default;
    private List<T> Many<T>(string sql, params object?[] values) {
        using var cmd = Command(sql, values); using var reader = cmd.ExecuteReader(); var list = new List<T>();
        while (reader.Read()) list.Add(Wire.Parse<T>(reader.GetString(0))); return list;
    }
    private long Revision() {
        var value = long.Parse((string)Scalar("SELECT json FROM settings WHERE id='revision'")!, CultureInfo.InvariantCulture) + 1;
        if (value > 9007199254740991) throw new VaultFault(503, "revision_exhausted");
        Execute("UPDATE settings SET json=$p0 WHERE id='revision'", value.ToString(CultureInfo.InvariantCulture)); return value;
    }
    public Admin? Administrator { get { lock (gate) return One<Admin>("SELECT json FROM settings WHERE id='admin'"); } }
    public void SetPassword(string password, bool reset = false) {
        if (password is null || password.Length is < 15 or > 128) throw new VaultFault(400, "invalid_password");
        lock (gate) {
            var old = Administrator;
            if (old is not null && !reset) throw new VaultFault(409, "already_initialized");
            var admin = new Admin(old?.Id ?? Guid.NewGuid().ToString(), "", Guid.NewGuid().ToString());
            admin = admin with { Hash = new PasswordHasher<Admin>().HashPassword(admin, password) };
            Execute("INSERT OR REPLACE INTO settings VALUES ('admin',$p0)", Wire.Serialize(admin));
        }
    }
    public Admin? Login(string password) {
        lock (gate) {
            var admin = Administrator;
            if (admin is null || password is null || password.Length > 128) return null;
            return new PasswordHasher<Admin>().VerifyHashedPassword(admin, admin.Hash, password) == PasswordVerificationResult.Failed ? null : admin;
        }
    }
    public Principal Authenticate(string token) {
        if (!Wire.IsToken(token)) throw new VaultFault(401, "unauthorized");
        lock (gate) {
            var record = One<TokenRecord>("SELECT json FROM tokens WHERE hash=$p0", Wire.HashToken(token));
            if (record is null || record.RevokedAt is not null || record.Info.ExpiresAt <= DateTimeOffset.UtcNow) throw new VaultFault(401, "unauthorized");
            if (record.LastUsedAt is null || record.LastUsedAt < DateTimeOffset.UtcNow.AddMinutes(-1)) SaveToken(record with { LastUsedAt = DateTimeOffset.UtcNow });
            return new(record.Info.Id, false, record.Info);
        }
    }
    private void SaveToken(TokenRecord token) => Execute("UPDATE tokens SET json=$p0 WHERE id=$p1", Wire.Serialize(token), token.Info.Id);
    public void Reserve(Principal principal, VaultRequest request) {
        lock (gate) {
            Execute("DELETE FROM replay WHERE expires < $p0", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            try { Execute("INSERT INTO replay VALUES ($p0,$p1,$p2)", principal.Id, request.RequestId, request.IssuedAt.AddSeconds(90).ToUnixTimeSeconds()); } catch (SqliteException ex) when (ex.SqliteErrorCode == 19) { throw new VaultFault(409, "replay_detected"); }
        }
    }
    public object Run(Principal principal, string operation, JsonElement parameters, string requestId, CancellationToken cancellationToken = default) {
        lock (gate) {
            cancellationToken.ThrowIfCancellationRequested();
            using var tx = db.BeginTransaction();
            try {
                var target = AuditTarget(parameters);
                var result = Dispatch(principal, operation, parameters);
                var after = AuditTarget(parameters);
                target = (target.BucketId ?? after.BucketId, target.SecretId ?? after.SecretId);
                cancellationToken.ThrowIfCancellationRequested();
                Audit(principal.Id, operation, requestId, "success", target.BucketId, target.SecretId); tx.Commit(); return result;
            } catch (VaultFault ex) {
                tx.Rollback(); Audit(principal.Id, operation, requestId, ex.Code); throw;
            }
        }
    }
    private (string? BucketId, string? SecretId) AuditTarget(JsonElement parameters) {
        if (parameters.ValueKind != JsonValueKind.Object) return (null, null);
        var name = parameters.TryGetProperty("bucket", out var b) ? b : parameters.TryGetProperty("name", out var n) ? n : default;
        if (name.ValueKind != JsonValueKind.String) return (null, null);
        var id = Scalar("SELECT id FROM buckets WHERE name=$p0", name.GetString()) as string;
        var secretId = id is not null && parameters.TryGetProperty("key", out var k) && k.ValueKind == JsonValueKind.String
            ? Scalar("SELECT id FROM entries WHERE bucket=$p0 AND name=$p1", id, k.GetString()) as string : null;
        return (id, secretId);
    }
    private void Audit(string principal, string operation, string requestId, string result, string? bucketId = null, string? secretId = null) {
        var now = DateTimeOffset.UtcNow;
        Execute("DELETE FROM audit WHERE time < $p0", now.AddDays(-90).ToString("O"));
        Execute("INSERT INTO audit(time,json) VALUES ($p0,$p1)", now.ToString("O"), Wire.Serialize(new { time = now, principal, operation, bucketId, secretId, requestId, result }));
    }
    public void RecordFailure(string principal, string operation, string result) {
        lock (gate) Audit(principal, operation, Guid.NewGuid().ToString(), result);
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
    private static object Page<T>(IEnumerable<T> values, Func<T, string> id, JsonElement p) {
        var (cursor, limit) = Paging(p);
        var items = values.OrderBy(id, StringComparer.Ordinal).Where(v => string.CompareOrdinal(id(v), cursor) > 0).Take(limit + 1).ToArray();
        return new Page<T>(items.Take(limit).ToArray(), items.Length > limit ? Wire.Base64(Encoding.UTF8.GetBytes(id(items[limit - 1]))) : null);
    }
    private object Dispatch(Principal p, string op, JsonElement args) {
        if (op == "token.info") { Fields(args); if (p.IsAdmin) throw new VaultFault(400, "invalid_request"); return p.Token!; }
        if (op.StartsWith("token.", StringComparison.Ordinal) || op == "audit.list") return AdminCommand(p, op, args);
        if (op == "bucket.list") {
            Fields(args, "cursor", "limit"); Require(p, "bucket:list");
            return Page(Many<Bucket>("SELECT json FROM buckets").Where(b => Allowed(p, b.Id)), b => b.Id, args);
        }
        if (op == "bucket.create") {
            Fields(args, "name", "description"); Require(p, "bucket:create");
            var name = Text(args, "name", 63); ValidateName(name);
            if (!p.IsAdmin && !p.Token!.AllBuckets && !p.Token.CreatableBucketNames.Contains(name)) throw new VaultFault(403, "forbidden");
            if (Scalar("SELECT id FROM buckets WHERE name=$p0", name) is not null) throw new VaultFault(409, "already_exists");
            var now = DateTimeOffset.UtcNow;
            var b = new Bucket(Guid.NewGuid().ToString(), name, Text(args, "description", 1024, true), Revision(), now, now);
            Execute("INSERT INTO buckets VALUES ($p0,$p1,$p2)", b.Id, b.Name, Wire.Serialize(b));
            if (!p.IsAdmin && !p.Token!.AllBuckets) {
                var token = One<TokenRecord>("SELECT json FROM tokens WHERE id=$p0", p.Id)!;
                SaveToken(token with { Info = token.Info with { BucketIds = [.. token.Info.BucketIds, b.Id], CreatableBucketNames = token.Info.CreatableBucketNames.Where(n => n != name).ToArray() } });
            }
            return b;
        }
        var bucketName = Text(args, "bucket", 63); ValidateName(bucketName);
        var bucket = One<Bucket>("SELECT json FROM buckets WHERE name=$p0", bucketName);
        if (bucket is null || !Allowed(p, bucket.Id)) throw new VaultFault(404, "not_found");
        if (op == "bucket.get") { Fields(args, "bucket"); Require(p, "bucket:read"); return bucket; }
        if (op == "bucket.read") {
            Fields(args, "bucket"); Require(p, "bucket:read", "secret:read", "secret:list");
            return new BucketSnapshot(bucket.Id, bucket.Revision, Values(bucket.Id));
        }
        if (op == "bucket.update") {
            if (!args.TryGetProperty("description", out _)) throw new VaultFault(400, "invalid_request");
            Fields(args, "bucket", "description", "expectedRevision"); Require(p, "bucket:write"); Match(Expected(args), bucket.Revision);
            bucket = bucket with { Description = Text(args, "description", 1024, true), Revision = Revision(), UpdatedAt = DateTimeOffset.UtcNow };
            SaveBucket(bucket); return bucket;
        }
        if (op == "bucket.delete") {
            Fields(args, "bucket", "expectedRevision", "recursive"); Require(p, "bucket:delete"); Match(Expected(args), bucket.Revision);
            var recursive = Boolean(args, "recursive");
            if (recursive) Require(p, "secret:delete");
            if (!recursive && (long)Scalar("SELECT count(*) FROM entries WHERE bucket=$p0", bucket.Id)! > 0) throw new VaultFault(409, "bucket_not_empty");
            Execute("DELETE FROM buckets WHERE id=$p0", bucket.Id); Revision(); return new { deleted = true };
        }
        if (op == "secret.list") {
            Fields(args, "bucket", "cursor", "limit"); Require(p, "secret:list");
            return Page(Many<StoredSecret>("SELECT json FROM entries WHERE bucket=$p0", bucket.Id).Select(s => s.Metadata), m => m.Id, args);
        }
        var key = Text(args, "key");
        if (key.Any(char.IsControl)) throw new VaultFault(400, "invalid_key");
        var old = One<StoredSecret>("SELECT json FROM entries WHERE bucket=$p0 AND name=$p1", bucket.Id, key);
        if (op == "secret.read") {
            Fields(args, "bucket", "key"); Require(p, "secret:read");
            if (old is null) throw new VaultFault(404, "not_found");
            var m = old.Metadata; return new Secret(m.Id, m.BucketId, m.Key, m.Revision, m.CreatedAt, m.UpdatedAt, ring.Decrypt(old.Value, m));
        }
        if (op == "secret.delete") {
            Fields(args, "bucket", "key", "expectedRevision"); Require(p, "secret:delete");
            if (old is null) throw new VaultFault(404, "not_found"); Match(Expected(args), old.Metadata.Revision);
            Execute("DELETE FROM entries WHERE id=$p0", old.Metadata.Id);
            SaveBucket(bucket with { Revision = Revision(), UpdatedAt = DateTimeOffset.UtcNow }); return new { deleted = true };
        }
        if (op is not ("secret.create" or "secret.update" or "secret.set")) throw new VaultFault(400, "unknown_operation");
        Fields(args, op == "secret.create" ? ["bucket", "key", "value"] : ["bucket", "key", "value", "expectedRevision"]);
        Require(p, "secret:write");
        if (op == "secret.create" && old is not null) throw new VaultFault(409, "already_exists");
        if (op == "secret.update" && old is null) throw new VaultFault(404, "not_found");
        if (op != "secret.create") Match(Expected(args), old?.Metadata.Revision ?? 0);
        if (!args.TryGetProperty("value", out var input) || input.ValueKind != JsonValueKind.String) throw new VaultFault(400, "invalid_request");
        var value = input.GetString()!;
        if (Encoding.UTF8.GetByteCount(value) > 65536) throw new VaultFault(413, "payload_too_large");
        var values = Values(bucket.Id); values[key] = value;
        if (values.Count > 4096 || Encoding.UTF8.GetByteCount(Wire.Serialize(values)) > 1024 * 1024) throw new VaultFault(413, "payload_too_large");
        var time = DateTimeOffset.UtcNow;
        var meta = new SecretMetadata(old?.Metadata.Id ?? Guid.NewGuid().ToString(), bucket.Id, key, Revision(), old?.Metadata.CreatedAt ?? time, time);
        SaveSecret(meta, value);
        SaveBucket(bucket with { Revision = meta.Revision, UpdatedAt = time }); return meta;
    }
    private void SaveSecret(SecretMetadata meta, string value) {
        for (var attempt = 0; attempt < 3; attempt++) {
            var secret = new StoredSecret(meta, ring.Encrypt(value, meta));
            try {
                Execute("INSERT INTO entries VALUES ($p0,$p1,$p2,$p3,$p4,$p5) ON CONFLICT(id) DO UPDATE SET json=$p3,keyid=$p4,nonce=$p5",
                    meta.Id, meta.BucketId, meta.Key, Wire.Serialize(secret), secret.Value.KeyId, secret.Value.Nonce);
                return;
            } catch (SqliteException ex) when (ex.SqliteErrorCode == 19 &&
                (long)Scalar("SELECT count(*) FROM entries WHERE keyid=$p0 AND nonce=$p1", secret.Value.KeyId, secret.Value.Nonce)! > 0) { }
        }
        throw new CryptographicException("Unable to allocate a unique nonce.");
    }
    private void SaveBucket(Bucket b) => Execute("UPDATE buckets SET json=$p0 WHERE id=$p1", Wire.Serialize(b), b.Id);
    private Dictionary<string, string?> Values(string bucket) => Many<StoredSecret>("SELECT json FROM entries WHERE bucket=$p0", bucket)
        .ToDictionary(s => s.Metadata.Key, s => (string?)ring.Decrypt(s.Value, s.Metadata), StringComparer.Ordinal);
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
                if (e.ValueKind == JsonValueKind.Null) expiry = null;
                else if (e.ValueKind == JsonValueKind.String && e.TryGetDateTimeOffset(out var dt) && dt.Offset == TimeSpan.Zero) expiry = dt;
                else throw new VaultFault(400, "invalid_request");
            }
            if (expiry <= DateTimeOffset.UtcNow) throw new VaultFault(400, "invalid_request");
            var token = Wire.NewToken();
            var info = new TokenInfo(Guid.NewGuid().ToString(), name, scopes, buckets, all, names, expiry);
            var record = new TokenRecord(info, DateTimeOffset.UtcNow, null, null);
            Execute("INSERT INTO tokens VALUES ($p0,$p1,$p2)", info.Id, Wire.HashToken(token), Wire.Serialize(record));
            return new { metadata = record, token };
        }
        if (op == "token.list") { Fields(args, "cursor", "limit"); return Page(Many<TokenRecord>("SELECT json FROM tokens"), t => t.Info.Id, args); }
        if (op == "token.revoke") {
            Fields(args, "id"); var id = Text(args, "id");
            var token = One<TokenRecord>("SELECT json FROM tokens WHERE id=$p0", id) ?? throw new VaultFault(404, "not_found");
            SaveToken(token with { RevokedAt = token.RevokedAt ?? DateTimeOffset.UtcNow }); return new { revoked = true };
        }
        if (op == "audit.list") {
            Fields(args, "cursor", "limit"); var (cursor, limit) = Paging(args);
            if (cursor == "") cursor = "0";
            if (!long.TryParse(cursor, out var after)) throw new VaultFault(400, "invalid_cursor");
            using var cmd = Command("SELECT id,json FROM audit WHERE id > $p0 ORDER BY id LIMIT $p1", after, limit + 1);
            using var r = cmd.ExecuteReader(); var items = new List<JsonElement>(); var ids = new List<long>();
            while (r.Read()) { ids.Add(r.GetInt64(0)); items.Add(JsonSerializer.Deserialize<JsonElement>(r.GetString(1))); }
            return new { items = items.Take(limit), nextCursor = ids.Count > limit ? Wire.Base64(Encoding.UTF8.GetBytes(ids[limit - 1].ToString(CultureInfo.InvariantCulture))) : null };
        }
        throw new VaultFault(400, "unknown_operation");
    }
    public void Reencrypt() {
        lock (gate) {
            ring.RotateData();
            foreach (var stored in Many<StoredSecret>("SELECT json FROM entries")) {
                using var tx = db.BeginTransaction();
                SaveSecret(stored.Metadata, ring.Decrypt(stored.Value, stored.Metadata));
                tx.Commit();
            }
        }
    }
    public void Verify() { lock (gate) { foreach (var s in Many<StoredSecret>("SELECT json FROM entries")) _ = ring.Decrypt(s.Value, s.Metadata); _ = Scalar("SELECT count(*) FROM buckets"); } }
    public void Ready() { lock (gate) { _ = Scalar("SELECT 1"); _ = ring.Public(); } }
    public void Backup(string destination) { lock (gate) { if (File.Exists(destination)) throw new IOException("Backup destination exists."); using var target = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = destination, Pooling = false }.ToString()); target.Open(); db.BackupDatabase(target); } }
    public sealed record Admin(string Id, string Hash, string Stamp);
    public sealed record Principal(string Id, bool IsAdmin, TokenInfo? Token = null);
    public sealed record TokenRecord(TokenInfo Info, DateTimeOffset CreatedAt, DateTimeOffset? RevokedAt, DateTimeOffset? LastUsedAt);
    public sealed record StoredSecret(SecretMetadata Metadata, EncryptedValue Value);
}
