using System.Security.Cryptography;
using System.Text;
using DarkVault.Client;

namespace DarkVault.Server;

public sealed class KeyRing {
    private readonly string path;
    private readonly object gate = new();
    private Ring state;
    public string ServerId => state.ServerId;
    public KeyRing(string path, bool create) {
        this.path = Path.GetFullPath(path);
        if (File.Exists(path)) state = ServerJson.Parse<Ring>(File.ReadAllText(path));
        else {
            if (!create) throw new InvalidOperationException("Keyring missing. Restore it before opening this database.");
            state = new(); RotateData(); RotateTransport();
        }
    }
    public static void SavePrivate(string path, string content) {
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Options = FileOptions.WriteThrough };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        try {
            using (var stream = new FileStream(tmp, options)) {
                var bytes = Encoding.UTF8.GetBytes(content); stream.Write(bytes); stream.Flush(true);
            }
            File.Move(tmp, path, true);
        } finally { if (File.Exists(tmp)) File.Delete(tmp); }
    }
    private void Save() => SavePrivate(path, ServerJson.Serialize(state));
    public void RotateData() {
        lock (gate) {
            var key = new DataKey(Guid.NewGuid().ToString(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), 0);
            state.Data.Add(key); state.ActiveData = key.Id; Save();
        }
    }
    public void RotateTransport(bool emergency = false) {
        lock (gate) {
            using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            if (emergency) state.Transport.Clear();
            state.Transport.RemoveAll(k => k.NotAfter.AddMinutes(10) < DateTimeOffset.UtcNow);
            state.Transport.Add(new(Guid.NewGuid().ToString(), Convert.ToBase64String(ec.ExportPkcs8PrivateKey()), DateTimeOffset.UtcNow.AddDays(30)));
            Save();
        }
    }
    public CryptoKey Public() {
        lock (gate) {
            if (state.Transport.Count == 0 || state.Transport[^1].NotAfter <= DateTimeOffset.UtcNow) RotateTransport();
            var active = state.Transport[^1];
            using var ec = Load(active.PrivateKey);
            return new(1, state.ServerId, DateTimeOffset.UtcNow, active.Id, Wire.Export(ec), active.NotAfter,
                new TransportLimits(Wire.MaxBody, Wire.MaxPlaintext));
        }
    }
    public string DecryptRequest(string compact) {
        var kid = Wire.Header(compact, "darkvault-request+jwe");
        lock (gate) {
            var key = state.Transport.Find(k => k.Id == kid && k.NotAfter.AddMinutes(10) > DateTimeOffset.UtcNow);
            if (key is null) throw new VaultFault(400, "unknown_key");
            using var ec = Load(key.PrivateKey);
            return Wire.Decrypt(compact, ec, kid, "darkvault-request+jwe");
        }
    }
    private static ECDsa Load(string encoded) {
        var ec = ECDsa.Create(); ec.ImportPkcs8PrivateKey(Convert.FromBase64String(encoded), out _); return ec;
    }
    public EncryptedValue Encrypt(string value, SecretMetadata metadata) {
        lock (gate) {
            var index = state.Data.FindIndex(k => k.Id == state.ActiveData);
            if (state.Data[index].Uses >= 1 << 20) { RotateData(); index = state.Data.Count - 1; }
            var key = state.Data[index];
            state.Data[index] = key with { Uses = key.Uses + 1 }; Save();
            var nonce = RandomNumberGenerator.GetBytes(12); var tag = new byte[16];
            var plain = Encoding.UTF8.GetBytes(value); var cipher = new byte[plain.Length];
            var bytes = Convert.FromBase64String(key.Key);
            try { using var aes = new AesGcm(bytes, 16); aes.Encrypt(nonce, plain, cipher, tag, Aad(metadata)); } finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(plain); }
            return new(1, key.Id, Wire.Base64(nonce), Wire.Base64(tag), Wire.Base64(cipher));
        }
    }
    public string Decrypt(EncryptedValue value, SecretMetadata metadata) {
        lock (gate) {
            if (value.FormatVersion != 1) throw new CryptographicException("Unknown storage format.");
            var key = state.Data.Find(k => k.Id == value.KeyId) ?? throw new CryptographicException("Missing data key.");
            var bytes = Convert.FromBase64String(key.Key); var cipher = Wire.Unbase64(value.Ciphertext); var plain = new byte[cipher.Length];
            try {
                using var aes = new AesGcm(bytes, 16);
                aes.Decrypt(Wire.Unbase64(value.Nonce), cipher, Wire.Unbase64(value.Tag), plain, Aad(metadata));
                return new UTF8Encoding(false, true).GetString(plain);
            } finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(plain); }
        }
    }
    public static byte[] Aad(SecretMetadata m) => Encoding.UTF8.GetBytes(ServerJson.Serialize(new object[] { 1, m.Id, m.BucketId, m.Key, m.Revision }));
    public sealed class Ring {
        public string ServerId { get; set; } = Guid.NewGuid().ToString();
        public string ActiveData { get; set; } = "";
        public List<DataKey> Data { get; set; } = [];
        public List<TransportKey> Transport { get; set; } = [];
    }
    public sealed record DataKey(string Id, string Key, long Uses);
    public sealed record TransportKey(string Id, string PrivateKey, DateTimeOffset NotAfter);
}
public sealed record EncryptedValue(int FormatVersion, string KeyId, string Nonce, string Tag, string Ciphertext);
public sealed class VaultFault(int status, string code) : Exception(code) {
    public int Status { get; } = status;
    public string Code { get; } = code;
}
