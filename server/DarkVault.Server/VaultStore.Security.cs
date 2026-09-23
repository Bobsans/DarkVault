using Microsoft.AspNetCore.Identity;

namespace DarkVault.Server;

public sealed partial class VaultStore {
    public sealed record MfaState(UserPasskeyInfo[] Passkeys, string[] RecoveryHashes);
    public MfaState Mfa { get { lock (gate) return One<MfaState>("SELECT json FROM settings WHERE id='mfa'") ?? new([], []); } }

    public Admin ConsumeRecovery(Admin expected, string code, RequestAudit context) {
        lock (gate) {
            var admin = CurrentAdmin(expected); var state = Mfa;
            var hash = Wire.HashToken(code);
            if (code.Length > 128 || !state.RecoveryHashes.Contains(hash)) throw new VaultFault(401, "unauthorized");
            using var tx = db.BeginTransaction();
            SaveMfa(state with { RecoveryHashes = state.RecoveryHashes.Where(h => h != hash).ToArray() });
            admin = ChangeStamp(admin);
            AuditSecurity(admin, "admin.recovery", context); tx.Commit(); return admin;
        }
    }

    public (Admin Admin, string[] RecoveryCodes) RegisterPasskey(Admin expected, UserPasskeyInfo passkey, bool replace, bool first, RequestAudit context) {
        lock (gate) {
            var admin = CurrentAdmin(expected); var state = Mfa;
            if (first && state.Passkeys.Length != 0) throw new VaultFault(409, "mfa_changed");
            if (!replace && state.Passkeys.Length >= 8) throw new VaultFault(409, "passkey_limit");
            if (state.Passkeys.Any(p => p.CredentialId.SequenceEqual(passkey.CredentialId))) throw new VaultFault(409, "credential_exists");
            var codes = first || replace ? Enumerable.Range(0, 8).Select(_ => "dvrc_" + Wire.Base64(System.Security.Cryptography.RandomNumberGenerator.GetBytes(24))).ToArray() : [];
            using var tx = db.BeginTransaction();
            SaveMfa(new(replace ? [passkey] : [.. state.Passkeys, passkey], codes.Length > 0 ? codes.Select(Wire.HashToken).ToArray() : state.RecoveryHashes));
            admin = ChangeStamp(admin); AuditSecurity(admin, "admin.mfa.register", context); tx.Commit(); return (admin, codes);
        }
    }

    public Admin CompletePasskey(Admin expected, UserPasskeyInfo passkey, RequestAudit context) {
        lock (gate) {
            var admin = CurrentAdmin(expected); var state = Mfa;
            var previous = state.Passkeys.SingleOrDefault(p => p.CredentialId.SequenceEqual(passkey.CredentialId)) ?? throw new VaultFault(401, "unauthorized");
            if (previous.SignCount != 0 && passkey.SignCount <= previous.SignCount) throw new VaultFault(401, "unauthorized");
            using var tx = db.BeginTransaction();
            SaveMfa(state with { Passkeys = state.Passkeys.Select(p => p.CredentialId.SequenceEqual(passkey.CredentialId) ? passkey : p).ToArray() });
            AuditSecurity(admin, "admin.mfa.verify", context); tx.Commit(); return admin;
        }
    }

    public void ResetMfa() {
        lock (gate) {
            var admin = Administrator ?? throw new VaultFault(401, "unauthorized");
            using var tx = db.BeginTransaction(); SaveMfa(new([], [])); admin = ChangeStamp(admin);
            AuditSecurity(admin, "admin.mfa.reset", null); tx.Commit();
        }
    }
    private Admin CurrentAdmin(Admin expected) => Administrator is { } admin && admin.Id == expected.Id && admin.Stamp == expected.Stamp ? admin : throw new VaultFault(401, "unauthorized");
    private Admin ChangeStamp(Admin admin) {
        admin = admin with { Stamp = Guid.NewGuid().ToString() };
        Execute("UPDATE settings SET json=$p0 WHERE id='admin'", ServerJson.Serialize(admin)); return admin;
    }
    private void SaveMfa(MfaState state) => Execute("INSERT OR REPLACE INTO settings VALUES ('mfa',$p0)", ServerJson.Serialize(state));
    private void AuditSecurity(Admin admin, string operation, RequestAudit? context) => AuditOperation(new(admin.Id, true), operation,
        context?.TraceId ?? Guid.NewGuid().ToString(), "success", (null, null), new(null, null, null, null, null, []), context);
}
