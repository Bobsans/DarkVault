using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace DarkVault.Server;

public sealed class KeyRing : IDisposable {
    private readonly string path;
    private readonly object gate = new();
    private Ring state;
    private readonly byte[]? wrappingKey;
    private const long MaxDataKeyUses = 1 << 20;
    private const long DataUseReservation = 1024;
    private string? reservedDataKey;
    private long nextReservedUse;
    private long reservedUntil;
    public string ServerId => state.ServerId;
    public KeyRing(string path, bool create, byte[]? wrappingKey = null) {
        this.path = Path.GetFullPath(path);
        if (wrappingKey is not null && wrappingKey.Length != 32) throw new ArgumentException("A 256-bit wrapping key is required.");
        this.wrappingKey = wrappingKey?.ToArray();
        if (File.Exists(path)) {
            var json = File.ReadAllText(path);
            using var document = System.Text.Json.JsonDocument.Parse(json);
            if (document.RootElement.TryGetProperty("protection", out _)) {
                var envelope = ServerJson.Parse<ProtectedRing>(json);
                if (envelope.Protection != "aes-256-gcm" || this.wrappingKey is null) throw new CryptographicException("The keyring wrapping key is required.");
                var cipher = Wire.Unbase64(envelope.Ciphertext); var plain = new byte[cipher.Length];
                try {
                    using var aes = new AesGcm(this.wrappingKey, 16);
                    aes.Decrypt(Wire.Unbase64(envelope.Nonce), cipher, Wire.Unbase64(envelope.Tag), plain, "darkvault-keyring:v1"u8);
                    state = ServerJson.Parse<Ring>(new UTF8Encoding(false, true).GetString(plain));
                } finally { CryptographicOperations.ZeroMemory(plain); }
            } else state = ServerJson.Parse<Ring>(json);
        } else {
            if (!create) throw new InvalidOperationException("Keyring missing. Restore it before opening this database.");
            state = new(); RotateData(); RotateTransport();
        }
        ValidateState();
    }
    public static void SavePrivate(string path, string content, bool overwrite = true) {
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Options = FileOptions.WriteThrough };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        try {
            FileStream OpenPrivate() {
                if (!OperatingSystem.IsWindows()) return new FileStream(tmp, options);
                var security = new FileSecurity(); security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl, AccessControlType.Allow));
                return new FileInfo(tmp).Create(FileMode.CreateNew, FileSystemRights.Write, FileShare.None, 4096, FileOptions.WriteThrough, security);
            }
            using (var stream = OpenPrivate()) {
                var bytes = Encoding.UTF8.GetBytes(content);
                try { stream.Write(bytes); stream.Flush(true); } finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            File.Move(tmp, path, overwrite);
        } finally { if (File.Exists(tmp)) File.Delete(tmp); }
    }
    private void ValidateState() {
        if (!Guid.TryParse(state.ServerId, out _) || state.Data.Count == 0 || state.Data.All(k => k.Id != state.ActiveData) || state.Transport.Count == 0)
            throw new CryptographicException("Keyring has no valid active key state.");
        foreach (var key in state.Data) {
            if (string.IsNullOrWhiteSpace(key.Id) || key.Uses < 0) throw new CryptographicException("Invalid data key metadata.");
            byte[] bytes;
            try { bytes = Convert.FromBase64String(key.Key); } catch (FormatException ex) { throw new CryptographicException("Invalid data key.", ex); }
            if (bytes.Length != 32) throw new CryptographicException("Invalid data key.");
        }
        foreach (var transport in state.Transport) {
            if (string.IsNullOrWhiteSpace(transport.Id) || transport.NotAfter == default) throw new CryptographicException("Invalid transport key metadata.");
            using var ec = Load(transport.PrivateKey);
            var parameters = ec.ExportParameters(false);
            if (parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value || parameters.Q.X is null || parameters.Q.Y is null) throw new CryptographicException("Invalid transport key.");
        }
    }
    private void Save() {
        if (wrappingKey is null) { SavePrivate(path, ServerJson.Serialize(state)); return; }
        var plain = Encoding.UTF8.GetBytes(ServerJson.Serialize(state)); var cipher = new byte[plain.Length];
        var nonce = RandomNumberGenerator.GetBytes(12); var tag = new byte[16];
        try {
            using var aes = new AesGcm(wrappingKey, 16); aes.Encrypt(nonce, plain, cipher, tag, "darkvault-keyring:v1"u8);
            SavePrivate(path, ServerJson.Serialize(new ProtectedRing("aes-256-gcm", Wire.Base64(nonce), Wire.Base64(tag), Wire.Base64(cipher))));
        } finally { CryptographicOperations.ZeroMemory(plain); }
    }
    public void Protect() {
        lock (gate) {
            if (wrappingKey is null) throw new InvalidOperationException("Configure a wrapping key before protecting the keyring.");
            Save();
        }
    }
    public void Dispose() { if (wrappingKey is not null) CryptographicOperations.ZeroMemory(wrappingKey); }
    public sealed record ProtectedRing(string Protection, string Nonce, string Tag, string Ciphertext);
    public void RotateData() {
        lock (gate) {
            var key = new DataKey(Guid.NewGuid().ToString(), Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), 0);
            state.Data.Add(key); state.ActiveData = key.Id; Save();
        }
    }
    public void PruneUnusedDataKeys() {
        lock (gate) { state.Data.RemoveAll(key => key.Id != state.ActiveData); Save(); }
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
            if (index < 0) throw new CryptographicException("Keyring has no valid active data key.");
            var active = state.Data[index];
            if (active.Uses >= MaxDataKeyUses && (reservedDataKey != active.Id || nextReservedUse >= reservedUntil)) {
                RotateData(); index = state.Data.Count - 1; active = state.Data[index];
            }
            if (reservedDataKey != active.Id) {
                reservedDataKey = active.Id; nextReservedUse = active.Uses; reservedUntil = active.Uses;
            }
            if (nextReservedUse >= reservedUntil) {
                var reservedTo = Math.Min(MaxDataKeyUses, active.Uses + DataUseReservation);
                state.Data[index] = active with { Uses = reservedTo };
                try { Save(); } catch { state.Data[index] = active; throw; }
                reservedUntil = reservedTo; nextReservedUse = active.Uses;
            }
            // Persist a high-water mark before use; after a crash the unused tail is skipped, never reused.
            nextReservedUse++;
            var key = state.Data[index];
            var nonce = RandomNumberGenerator.GetBytes(12); var tag = new byte[16];
            var plain = Encoding.UTF8.GetBytes(value); var cipher = new byte[plain.Length];
            var bytes = Convert.FromBase64String(key.Key);
            try { using var aes = new AesGcm(bytes, 16); aes.Encrypt(nonce, plain, cipher, tag, Aad(metadata)); } finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(plain); }
            return new(2, key.Id, Wire.Base64(nonce), Wire.Base64(tag), Wire.Base64(cipher));
        }
    }
    public string Decrypt(EncryptedValue value, SecretMetadata metadata) {
        lock (gate) {
            if (value.FormatVersion is not (1 or 2) || (value.FormatVersion == 1 && metadata.Type != "string")) throw new CryptographicException("Unknown storage format or type.");
            var key = state.Data.Find(k => k.Id == value.KeyId) ?? throw new CryptographicException("Missing data key.");
            var bytes = Convert.FromBase64String(key.Key); var cipher = Wire.Unbase64(value.Ciphertext); var plain = new byte[cipher.Length];
            try {
                using var aes = new AesGcm(bytes, 16);
                var aad = value.FormatVersion == 1 ? Encoding.UTF8.GetBytes(ServerJson.Serialize(new object[] { 1, metadata.Id, metadata.BucketId, metadata.Key, metadata.Revision })) : Aad(metadata);
                aes.Decrypt(Wire.Unbase64(value.Nonce), cipher, Wire.Unbase64(value.Tag), plain, aad);
                return new UTF8Encoding(false, true).GetString(plain);
            } finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(plain); }
        }
    }
    public static byte[] Aad(SecretMetadata m) => Encoding.UTF8.GetBytes(ServerJson.Serialize(new object[] { 2, m.Id, m.BucketId, m.Key, m.Revision, m.Type }));
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
