using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DarkVault.Client;
using DarkVault.Server;
using Microsoft.Data.Sqlite;
using NUnit.Framework;

namespace DarkVault.Server.Tests;

[TestFixture]
public sealed class VaultStoreTests {
    private string directory = null!;
    private KeyRing ring = null!;
    private VaultStore store = null!;
    private readonly VaultStore.Principal admin = new("test-admin", true);
    [SetUp]
    public void SetUp() {
        directory = Path.Combine(Path.GetTempPath(), "darkvault-test-" + Guid.NewGuid()); Directory.CreateDirectory(directory);
        ring = new(Path.Combine(directory, "keyring.json"), true); store = new(Path.Combine(directory, "vault.db"), ring);
    }
    [TearDown] public void TearDown() { store.Dispose(); Directory.Delete(directory, true); }
    private T Run<T>(string operation, object args, VaultStore.Principal? p = null) =>
        JsonSerializer.SerializeToElement(store.Run(p ?? admin, operation, JsonSerializer.SerializeToElement(args, Wire.Json), Guid.NewGuid().ToString()), Wire.Json).Deserialize<T>(Wire.ResponseJson)!;
    private string Token(string[] scopes, string[] buckets, DateTimeOffset? expiry = null, bool all = false, string[]? names = null) =>
        Run<JsonElement>("token.create", new { name = "test", scopes, bucketIds = buckets, allBuckets = all, creatableBucketNames = names ?? [], expiresAt = expiry }).GetProperty("token").GetString()!;
    [Test]
    public void TokenFormatScopesExpiryRevocationAndIsolation() {
        var qa = Run<Bucket>("bucket.create", new { name = "qa" }); var prod = Run<Bucket>("bucket.create", new { name = "prod" });
        Run<SecretMetadata>("secret.create", new { bucket = "qa", key = "A", value = "secret" });
        var token = Token(["bucket:read", "secret:read", "secret:list", "bucket:list"], [qa.Id]);
        Assert.That(token, Has.Length.EqualTo(64)); Assert.That(Wire.IsToken(token), Is.True);
        var p = store.Authenticate(token);
        Assert.That(Run<BucketSnapshot>("bucket.read", new { bucket = "qa" }, p).Secrets["A"], Is.EqualTo("secret"));
        Assert.That(Run<Page<Bucket>>("bucket.list", new { }, p).Items.Select(b => b.Name), Is.EqualTo(new[] { "qa" }));
        Assert.That(Assert.Throws<VaultFault>(() => Run<Bucket>("bucket.get", new { bucket = "prod" }, p))!.Status, Is.EqualTo(404));
        Assert.That(Assert.Throws<VaultFault>(() => Run<JsonElement>("secret.create", new { bucket = "qa", key = "B", value = "x" }, p))!.Status, Is.EqualTo(403));
        Run<JsonElement>("token.revoke", new { id = p.Id }); Assert.Throws<VaultFault>(() => store.Authenticate(token));
        var replacement = Token(["secret:read"], [qa.Id]);
        Assert.That(Run<Secret>("secret.read", new { bucket = "qa", key = "A" }, store.Authenticate(replacement)).Value, Is.EqualTo("secret"));
        Assert.Throws<VaultFault>(() => Token([], [], DateTimeOffset.UtcNow.AddSeconds(-1)));
        var expires = Token([], [], DateTimeOffset.UtcNow.AddMilliseconds(200)); Thread.Sleep(250);
        Assert.Throws<VaultFault>(() => store.Authenticate(expires));
        store.Dispose();
        var db = File.ReadAllBytes(Path.Combine(directory, "vault.db"));
        Assert.That(Encoding.UTF8.GetString(db), Does.Not.Contain(token));
    }
    [Test]
    public void EveryScopeIsRequiredAndIndependent() {
        var bucket = Run<Bucket>("bucket.create", new { name = "qa" });
        var secret = Run<SecretMetadata>("secret.create", new { bucket = "qa", key = "A", value = "x" });
        var cases = new (string Op, object Args, string[] Scopes)[] {
            ("bucket.list", new {}, ["bucket:list"]), ("bucket.get",new {bucket="qa"},["bucket:read"]),
            ("bucket.read",new {bucket="qa"},["bucket:read","secret:read","secret:list"]),
            ("bucket.create",new {name="new"},["bucket:create"]),
            ("bucket.update",new {bucket="qa",description="x",expectedRevision=secret.Revision},["bucket:write"]),
            ("bucket.delete",new {bucket="qa",recursive=true,expectedRevision=secret.Revision},["bucket:delete","secret:delete"]),
            ("secret.list",new {bucket="qa"},["secret:list"]), ("secret.read",new {bucket="qa",key="A"},["secret:read"]),
            ("secret.create",new {bucket="qa",key="B",value="x"},["secret:write"]),
            ("secret.update",new {bucket="qa",key="A",value="x",expectedRevision=secret.Revision},["secret:write"]),
            ("secret.set",new {bucket="qa",key="A",value="x",expectedRevision=secret.Revision},["secret:write"]),
            ("secret.delete",new {bucket="qa",key="A",expectedRevision=secret.Revision},["secret:delete"])
        };
        foreach (var test in cases) foreach (var missing in test.Scopes) {
            var scopes = VaultStore.Scopes.Where(s => s != missing).ToArray();
            var p = store.Authenticate(Token(scopes, [bucket.Id], all: true));
            Assert.That(Assert.Throws<VaultFault>(() => Run<JsonElement>(test.Op, test.Args, p))!.Status, Is.EqualTo(403), test.Op + " requires " + missing);
        }
    }
    [Test]
    public void RevisionCreateGrantAndRecursiveDeleteAreAtomic() {
        var token = Token(VaultStore.Scopes, [], names: ["qa"]); var p = store.Authenticate(token);
        var b = Run<Bucket>("bucket.create", new { name = "qa" }, p); p = store.Authenticate(token);
        Assert.That(p.Token!.BucketIds, Does.Contain(b.Id)); Assert.That(p.Token.CreatableBucketNames, Is.Empty);
        var s = Run<SecretMetadata>("secret.create", new { bucket = "qa", key = "k", value = "" }, p);
        Assert.Throws<VaultFault>(() => Run<JsonElement>("secret.set", new { bucket = "qa", key = "k", value = "lost", expectedRevision = 0 }, p));
        Assert.Throws<VaultFault>(() => Run<JsonElement>("bucket.delete", new { bucket = "qa", expectedRevision = s.Revision }, p));
        Run<JsonElement>("secret.delete", new { bucket = "qa", key = "k", expectedRevision = s.Revision }, p);
        var next = Run<SecretMetadata>("secret.create", new { bucket = "qa", key = "k", value = "new" }, p);
        Assert.That(next.Revision, Is.GreaterThan(s.Revision));
        Assert.Throws<VaultFault>(() => Run<JsonElement>("secret.delete", new { bucket = "qa", key = "k", expectedRevision = s.Revision }, p));
        Run<JsonElement>("bucket.delete", new { bucket = "qa", expectedRevision = next.Revision, recursive = true }, p);
        Run<Bucket>("bucket.create", new { name = "qa" });
        Assert.Throws<VaultFault>(() => Run<Bucket>("bucket.get", new { bucket = "qa" }, store.Authenticate(token)));
    }
    [Test]
    public void EncryptedStorageRotationBackupAndCorruption() {
        Run<Bucket>("bucket.create", new { name = "qa" });
        Run<SecretMetadata>("secret.create", new { bucket = "qa", key = "ConnectionStrings:Main", value = "秘密\nline" });
        store.Reencrypt(); store.Verify();
        var before = Run<BucketSnapshot>("bucket.read", new { bucket = "qa" });
        var copy = Path.Combine(directory, "copy.db"); store.Backup(copy);
        using (var restored = new VaultStore(copy, new KeyRing(Path.Combine(directory, "keyring.json"), false))) restored.Verify();
        Assert.That(before.Secrets["ConnectionStrings:Main"], Is.EqualTo("秘密\nline"));
        var meta = new SecretMetadata(Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), "key", 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        var value = ring.Encrypt("secret", meta);
        Assert.Throws<AuthenticationTagMismatchException>(() => ring.Decrypt(value, meta with { Key = "other" }));
        Assert.Throws<InvalidOperationException>(() => new KeyRing(Path.Combine(directory, "missing"), false));
    }
    [Test]
    public void ReplayPersistsAcrossRestart() {
        using var reply = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new VaultRequest(1, Guid.NewGuid().ToString(), DateTimeOffset.UtcNow, ring.ServerId, "admin", "bucket.list", JsonSerializer.SerializeToElement(new { }), Wire.Export(reply));
        store.Reserve(admin, request); store.Dispose(); store = new(Path.Combine(directory, "vault.db"), ring);
        Assert.That(Assert.Throws<VaultFault>(() => store.Reserve(admin, request))!.Code, Is.EqualTo("replay_detected"));
    }
    [Test]
    public void DiskFullRollsBackSecretAndBucketRevision() {
        var bucket = Run<Bucket>("bucket.create", new { name = "qa" });
        // Limit this test connection's page budget without filling the machine's disk.
        var db = (SqliteConnection)typeof(VaultStore).GetField("db", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(store)!;
        using var command = db.CreateCommand(); command.CommandText = "PRAGMA page_count";
        var pages = (long)command.ExecuteScalar()!; command.CommandText = "PRAGMA max_page_count=" + pages; command.ExecuteScalar();
        Assert.Throws<SqliteException>(() => Run<JsonElement>("secret.create", new { bucket = "qa", key = "large", value = new string('x', 65536) }));
        Assert.That(Run<Bucket>("bucket.get", new { bucket = "qa" }).Revision, Is.EqualTo(bucket.Revision));
        Assert.That(Run<BucketSnapshot>("bucket.read", new { bucket = "qa" }).Secrets, Is.Empty);
    }
    [Test]
    public void InvalidPaginationAndMissingDescriptionAreRejected() {
        var b = Run<Bucket>("bucket.create", new { name = "qa" });
        Assert.Throws<VaultFault>(() => Run<JsonElement>("bucket.list", new { limit = "100" }));
        Assert.Throws<VaultFault>(() => Run<JsonElement>("bucket.update", new { bucket = "qa", expectedRevision = b.Revision }));
        Assert.Throws<VaultFault>(() => Run<JsonElement>("bucket.create", new { name = "qa\n" }));
    }
    [Test]
    public void AuditRecordsObjectsActorsFailuresAndTokenPermissionsWithoutValues() {
        var bucket = Run<Bucket>("bucket.create", new { name = "test", description = "private-description" });
        var secret = Run<SecretMetadata>("secret.create", new { bucket = bucket.Name, key = "Main", value = "private-audit-value" });
        var token = Token(["secret:read"], [bucket.Id]); var actor = store.Authenticate(token);
        Run<Secret>("secret.read", new { bucket = bucket.Name, key = secret.Key }, actor);
        Assert.Throws<VaultFault>(() => Run<JsonElement>("secret.delete", new { bucket = bucket.Name, key = secret.Key, expectedRevision = secret.Revision }, actor));
        Run<BucketSnapshot>("bucket.read", new { bucket = bucket.Name });
        Run<Page<SecretMetadata>>("secret.list", new { bucket = bucket.Name });
        Run<JsonElement>("token.revoke", new { id = actor.Id });
        Run<JsonElement>("bucket.delete", new { bucket = bucket.Name, expectedRevision = secret.Revision, recursive = true });
        var audit = Run<Page<JsonElement>>("audit.list", new { limit = 200 });
        JsonElement Entry(string operation) => audit.Items.Single(e => e.GetProperty("operation").GetString() == operation);
        var read = Entry("secret.read");
        Assert.That(read.GetProperty("principal").GetString(), Is.EqualTo(actor.Id));
        Assert.That(read.GetProperty("principalType").GetString(), Is.EqualTo("token"));
        Assert.That(read.GetProperty("principalName").GetString(), Is.EqualTo("test"));
        Assert.That(read.GetProperty("secretId").GetString(), Is.EqualTo(secret.Id));
        Assert.That(read.GetProperty("details").GetProperty("resources")[0].GetProperty("revision").GetInt64(), Is.EqualTo(secret.Revision));
        var denied = Entry("secret.delete");
        Assert.That(denied.GetProperty("result").GetString(), Is.EqualTo("forbidden"));
        Assert.That(denied.GetProperty("details").GetProperty("key").GetString(), Is.EqualTo(secret.Key));
        Assert.That(denied.GetProperty("details").GetProperty("resources").GetArrayLength(), Is.Zero);
        foreach (var operation in new[] { "bucket.read", "secret.list", "bucket.delete" })
            Assert.That(Entry(operation).GetProperty("details").GetProperty("resources").EnumerateArray().Select(r => r.GetProperty("id").GetString()), Does.Contain(secret.Id));
        Assert.That(Entry("token.revoke").GetProperty("details").GetProperty("tokenId").GetString(), Is.EqualTo(actor.Id));
        Assert.That(Entry("token.create").GetProperty("details").GetProperty("token").GetProperty("scopes")[0].GetString(), Is.EqualTo("secret:read"));
        Assert.That(Entry("token.create").GetProperty("bucketId").ValueKind, Is.EqualTo(JsonValueKind.Null));
        var json = JsonSerializer.Serialize(audit, Wire.Json);
        Assert.That(json, Does.Not.Contain("private-audit-value").And.Not.Contain("private-description").And.Not.Contain(token));
        store.Dispose(); store = new(Path.Combine(directory, "vault.db"), ring);
        Assert.That(Run<Page<JsonElement>>("audit.list", new { limit = 200 }).Items.Count, Is.GreaterThan(audit.Items.Count));
    }
    [Test]
    public void SecretTypesSurviveStorageRotationAndRejectTampering() {
        Run<Bucket>("bucket.create", new { name = "typed" });
        var number = Run<SecretMetadata>("secret.create", new { bucket = "typed", key = "Count", value = "1e2", type = "number" });
        Run<SecretMetadata>("secret.create", new { bucket = "typed", key = "Enabled", value = "false", type = "boolean" });
        Run<SecretMetadata>("secret.create", new { bucket = "typed", key = "Nothing", value = "null", type = "null" });
        Run<SecretMetadata>("secret.create", new { bucket = "typed", key = "Text", value = "00123" });
        Assert.That(number.Type, Is.EqualTo("number"));
        foreach (var (value, type) in new[] { ("NaN", "number"), ("1e999", "number"), ("9007199254740992", "number"), ("yes", "boolean"), ("0", "null"), ("[]", "array") })
            Assert.That(Assert.Throws<VaultFault>(() => Run<JsonElement>("secret.set", new { bucket = "typed", key = "Invalid", value, type, expectedRevision = 0 }))!.Code, Is.EqualTo("invalid_secret_type"));
        var snapshot = Run<BucketSnapshot>("bucket.read", new { bucket = "typed" });
        Assert.That(snapshot.Secrets["Count"], Is.EqualTo("100"));
        Assert.That(snapshot.Types, Has.Count.EqualTo(3));
        Assert.That(SecretValues.Typed(snapshot)["Nothing"].ValueKind, Is.EqualTo(JsonValueKind.Null));
        var encrypted = ring.Encrypt("100", number);
        Assert.Throws<AuthenticationTagMismatchException>(() => ring.Decrypt(encrypted, number with { Type = "string" }));
        store.Reencrypt(); store.Verify(); store.Dispose(); store = new(Path.Combine(directory, "vault.db"), ring);
        Assert.That(Run<Secret>("secret.read", new { bucket = "typed", key = "Count" }).GetTypedValue().GetDouble(), Is.EqualTo(100));
        var revision = Run<Bucket>("bucket.get", new { bucket = "typed" }).Revision;
        Run<SecretMetadata>("secret.update", new { bucket = "typed", key = "Count", value = "true", type = "boolean", expectedRevision = number.Revision });
        Assert.That(Run<Bucket>("bucket.get", new { bucket = "typed" }).Revision, Is.GreaterThan(revision));
        Assert.That(Run<Secret>("secret.read", new { bucket = "typed", key = "Count" }).GetTypedValue().GetBoolean(), Is.True);
    }
    [Test]
    public void LegacyStringEncryptionRemainsReadableAndCannotAcquireAType() {
        var metadata = new SecretMetadata(Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), "key", 1, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
        using var state = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, "keyring.json")));
        var key = state.RootElement.GetProperty("data")[0];
        var plain = Encoding.UTF8.GetBytes("legacy-value"); var nonce = RandomNumberGenerator.GetBytes(12); var cipher = new byte[plain.Length]; var tag = new byte[16];
        using (var aes = new AesGcm(Convert.FromBase64String(key.GetProperty("key").GetString()!), 16))
            aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new object[] { 1, metadata.Id, metadata.BucketId, metadata.Key, metadata.Revision }, Wire.Json)));
        var encrypted = new EncryptedValue(1, key.GetProperty("id").GetString()!, Wire.Base64(nonce), Wire.Base64(tag), Wire.Base64(cipher));
        Assert.That(ring.Decrypt(encrypted, metadata), Is.EqualTo("legacy-value"));
        Assert.Throws<CryptographicException>(() => ring.Decrypt(encrypted, metadata with { Type = "number" }));
    }
    [Test]
    public void AuditFiltersAndDescendingPaginationSelectStoredEvents() {
        Run<Bucket>("bucket.create", new { name = "audit_filter" });
        Run<SecretMetadata>("secret.create", new { bucket = "audit_filter", key = "literal_%", value = "private" });
        Run<Secret>("secret.read", new { bucket = "audit_filter", key = "literal_%" });
        Assert.Throws<VaultFault>(() => Run<Secret>("secret.read", new { bucket = "audit_filter", key = "missing" }));
        var first = Run<Page<JsonElement>>("audit.list", new { order = "desc", search = "audit_filter", kind = "operation", result = "success", limit = 1 });
        Assert.That(first.Items.Single().GetProperty("operation").GetString(), Is.EqualTo("secret.read"));
        Assert.That(first.NextCursor, Is.Not.Null);
        var second = Run<Page<JsonElement>>("audit.list", new { order = "desc", search = "audit_filter", kind = "operation", result = "success", limit = 1, cursor = first.NextCursor });
        Assert.That(second.Items.Single().GetProperty("operation").GetString(), Is.EqualTo("secret.create"));
        var failed = Run<Page<JsonElement>>("audit.list", new { order = "desc", search = "audit_filter", result = "failure" });
        Assert.That(failed.Items.Single().GetProperty("result").GetString(), Is.EqualTo("not_found"));
        Assert.That(Run<Page<JsonElement>>("audit.list", new { search = "literal_%", order = "desc" }).Items.Count, Is.EqualTo(2));
        Assert.That(Run<Page<JsonElement>>("audit.list", new { kind = "http" }).Items, Is.Empty);
        Assert.That(Run<Page<JsonElement>>("audit.list", new { search = "' OR 1=1 --" }).Items, Is.Empty);
        Assert.Throws<VaultFault>(() => Run<JsonElement>("audit.list", new { order = "invalid" }));
        Assert.Throws<VaultFault>(() => Run<JsonElement>("audit.list", new { result = "invalid" }));
        Assert.Throws<VaultFault>(() => Run<JsonElement>("audit.list", new { kind = "invalid" }));
        Assert.Throws<VaultFault>(() => Run<JsonElement>("audit.list", new { search = new string('x', 257) }));
    }
    [Test]
    public void UnexpectedReadFailureIsAuditedWithoutExceptionDetails() {
        Run<Bucket>("bucket.create", new { name = "corrupt" });
        var secret = Run<SecretMetadata>("secret.create", new { bucket = "corrupt", key = "key", value = "private-corruption-value" });
        using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Path.Combine(directory, "vault.db"), Pooling = false }.ToString())) {
            connection.Open(); using var command = connection.CreateCommand();
            command.CommandText = "UPDATE entries SET json=json_set(json,'$.value.ciphertext','invalid-ciphertext')"; command.ExecuteNonQuery();
        }
        Assert.Catch(() => Run<Secret>("secret.read", new { bucket = "corrupt", key = "key" }));
        var entry = Run<Page<JsonElement>>("audit.list", new { }).Items.Single(e => e.GetProperty("operation").GetString() == "secret.read");
        Assert.That(entry.GetProperty("result").GetString(), Is.EqualTo("unavailable"));
        Assert.That(entry.GetProperty("secretId").GetString(), Is.EqualTo(secret.Id));
        Assert.That(entry.GetProperty("details").GetProperty("resources").GetArrayLength(), Is.Zero);
        Assert.That(entry.GetRawText(), Does.Not.Contain("invalid-ciphertext").And.Not.Contain("private-corruption-value"));
    }
    [Test]
    public void LargeAuditReadsPreserveAllObjectsAndFitTransportPages() {
        Run<Bucket>("bucket.create", new { name = "bulk" });
        for (var i = 0; i < 205; i++) Run<SecretMetadata>("secret.create", new { bucket = "bulk", key = new string('k', 120) + i, value = "" });
        string? cursor = null;
        for (var i = 0; i < 30; i++) Run<BucketSnapshot>("bucket.read", new { bucket = "bulk" });
        var entries = new List<JsonElement>();
        do {
            var page = Run<Page<JsonElement>>("audit.list", new { cursor, limit = 200 });
            Assert.That(Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(page, Wire.Json)), Is.LessThan(Wire.MaxPlaintext - 2048));
            entries.AddRange(page.Items); cursor = page.NextCursor;
        } while (cursor is not null);
        var reads = entries.Where(e => e.GetProperty("operation").GetString() == "bucket.read").GroupBy(e => e.GetProperty("requestId").GetString()).ToArray();
        Assert.That(reads, Has.Length.EqualTo(30));
        foreach (var read in reads) {
            Assert.That(read.SelectMany(e => e.GetProperty("details").GetProperty("resources").EnumerateArray()).Count(), Is.EqualTo(205));
            Assert.That(read.All(e => e.GetProperty("details").GetProperty("returnedCount").GetInt32() == 205), Is.True);
        }
    }
    [Test]
    public void LimitsAndPaginationDoNotLeakValues() {
        Run<Bucket>("bucket.create", new { name = "qa" });
        for (var i = 0; i < 3; i++) Run<SecretMetadata>("secret.create", new { bucket = "qa", key = "key" + i, value = "private-value" });
        var first = Run<Page<SecretMetadata>>("secret.list", new { bucket = "qa", limit = 2 });
        Assert.That(first.Items.Count, Is.EqualTo(2)); Assert.That(first.NextCursor, Is.Not.Null);
        var last = Run<Page<SecretMetadata>>("secret.list", new { bucket = "qa", limit = 2, cursor = first.NextCursor });
        Assert.That(last.Items.Count, Is.EqualTo(1)); Assert.That(last.NextCursor, Is.Null);
        Assert.That(Wire.Serialize(first), Does.Not.Contain("private-value"));
        Assert.That(Assert.Throws<VaultFault>(() => Run<JsonElement>("secret.create", new { bucket = "qa", key = "big", value = new string('x', 65537) }))!.Status, Is.EqualTo(413));
    }
}
