using Microsoft.AspNetCore.Identity;

namespace DarkVault.Server;

// Adapter for the platform WebAuthn verifier; the vault remains the only user store.
public sealed class AdminPasskeyStore(VaultStore store) : IUserPasskeyStore<VaultStore.Admin> {
    public Task<VaultStore.Admin?> FindByIdAsync(string userId, CancellationToken cancellationToken) => Task.FromResult(store.Administrator is { } admin && admin.Id == userId ? admin : null);
    public Task<VaultStore.Admin?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) => Task.FromResult(normalizedUserName == "ADMIN" ? store.Administrator : null);
    public Task<string> GetUserIdAsync(VaultStore.Admin user, CancellationToken cancellationToken) => Task.FromResult(user.Id);
    public Task<string?> GetUserNameAsync(VaultStore.Admin user, CancellationToken cancellationToken) => Task.FromResult<string?>("admin");
    public Task<string?> GetNormalizedUserNameAsync(VaultStore.Admin user, CancellationToken cancellationToken) => Task.FromResult<string?>("ADMIN");
    public Task<IList<UserPasskeyInfo>> GetPasskeysAsync(VaultStore.Admin user, CancellationToken cancellationToken) => Task.FromResult<IList<UserPasskeyInfo>>(store.Mfa.Passkeys);
    public Task<UserPasskeyInfo?> FindPasskeyAsync(VaultStore.Admin user, byte[] credentialId, CancellationToken cancellationToken) => Task.FromResult(store.Mfa.Passkeys.SingleOrDefault(p => p.CredentialId.SequenceEqual(credentialId)));
    public Task<VaultStore.Admin?> FindByPasskeyIdAsync(byte[] credentialId, CancellationToken cancellationToken) => Task.FromResult(store.Mfa.Passkeys.Any(p => p.CredentialId.SequenceEqual(credentialId)) ? store.Administrator : null);
    // Security changes use VaultStore's transactional, audited methods, never Identity CRUD.
    public Task<IdentityResult> CreateAsync(VaultStore.Admin user, CancellationToken cancellationToken) => throw new NotSupportedException();
    public Task<IdentityResult> UpdateAsync(VaultStore.Admin user, CancellationToken cancellationToken) => throw new NotSupportedException();
    public Task<IdentityResult> DeleteAsync(VaultStore.Admin user, CancellationToken cancellationToken) => throw new NotSupportedException();
    public Task SetUserNameAsync(VaultStore.Admin user, string? userName, CancellationToken cancellationToken) => throw new NotSupportedException();
    public Task SetNormalizedUserNameAsync(VaultStore.Admin user, string? normalizedName, CancellationToken cancellationToken) => throw new NotSupportedException();
    public Task AddOrUpdatePasskeyAsync(VaultStore.Admin user, UserPasskeyInfo passkey, CancellationToken cancellationToken) => throw new NotSupportedException();
    public Task RemovePasskeyAsync(VaultStore.Admin user, byte[] credentialId, CancellationToken cancellationToken) => throw new NotSupportedException();
    public void Dispose() { }
}
