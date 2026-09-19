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
