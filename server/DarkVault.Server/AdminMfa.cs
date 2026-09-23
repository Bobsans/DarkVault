using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Identity;

namespace DarkVault.Server;

public sealed class AdminMfa(TimeProvider clock) {
    private const string Cookie = "__Secure-DarkVault-Mfa";
    private readonly object gate = new();
    private readonly Dictionary<string, Challenge> pending = new();
    private sealed record Challenge(VaultStore.Admin Admin, string State, string Origin, bool Enroll, bool Replace, bool First, DateTimeOffset Expires);
    public sealed record OptionsResult(bool Authenticated, string Mode, System.Text.Json.JsonElement Options);
    public sealed record VerifyRequest(System.Text.Json.JsonElement Credential);
    public sealed record VerifyResult(bool Authenticated, string[] RecoveryCodes);

    public static void Configure(WebApplicationBuilder builder) {
        builder.Services.AddSingleton<AdminMfa>();
        builder.Services.AddIdentityCore<VaultStore.Admin>().AddUserStore<AdminPasskeyStore>();
        builder.Services.AddScoped<IPasskeyHandler<VaultStore.Admin>, PasskeyHandler<VaultStore.Admin>>();
        builder.Services.Configure<IdentityPasskeyOptions>(options => {
            var origin = builder.Configuration["DARKVAULT_PUBLIC_ORIGIN"];
            if (!string.IsNullOrEmpty(origin)) options.ServerDomain = ValidateOrigin(origin).Host;
            options.UserVerificationRequirement = "required";
            options.AuthenticatorTimeout = TimeSpan.FromMinutes(2);
            options.ValidateOrigin = context => ValueTask.FromResult(!context.CrossOrigin &&
                context.Origin == PublicOrigin(context.HttpContext) && context.HttpContext.Request.Headers.Origin == context.Origin);
        });
    }

    public static string PublicOrigin(HttpContext context) {
        var configured = context.RequestServices.GetRequiredService<IConfiguration>()["DARKVAULT_PUBLIC_ORIGIN"];
        if (configured is { Length: > 0 }) return ValidateOrigin(configured).GetLeftPart(UriPartial.Authority);
        // Without a canonical origin the request Host defines the WebAuthn origin, so only a loopback host is trusted.
        if (!IsLoopback(context.Request.Host.Host)) throw new VaultFault(400, "invalid_origin");
        return "https://" + context.Request.Host;
    }
    private static bool IsLoopback(string host) => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
        (System.Net.IPAddress.TryParse(host.Trim('[', ']'), out var address) && System.Net.IPAddress.IsLoopback(address));
    private static Uri ValidateOrigin(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme == "https" &&
        uri.UserInfo.Length == 0 && uri.AbsolutePath == "/" && uri.Query.Length == 0 && uri.Fragment.Length == 0 ? uri : throw new InvalidOperationException("DARKVAULT_PUBLIC_ORIGIN must be an HTTPS origin.");

    public async Task<OptionsResult> Begin(HttpContext context, VaultStore store, VaultStore.Admin admin, bool enroll, bool replace = false) {
        if (context.Request.Headers.Origin != PublicOrigin(context)) throw new VaultFault(400, "invalid_origin");
        var handler = context.RequestServices.GetRequiredService<IPasskeyHandler<VaultStore.Admin>>();
        string json, state;
        if (enroll) {
            var result = await handler.MakeCreationOptionsAsync(new() { Id = admin.Id, Name = "admin", DisplayName = "DarkVault administrator" }, context);
            json = result.CreationOptionsJson; state = result.AttestationState ?? throw new InvalidOperationException("Missing attestation state.");
        } else {
            var result = await handler.MakeRequestOptionsAsync(admin, context);
            json = result.RequestOptionsJson; state = result.AssertionState ?? throw new InvalidOperationException("Missing assertion state.");
        }
        lock (gate) {
            var now = clock.GetUtcNow();
            foreach (var key in pending.Where(p => p.Value.Expires <= now).Select(p => p.Key).ToArray()) pending.Remove(key);
            if (context.Request.Cookies[Cookie] is { } previous) pending.Remove(Wire.HashToken(previous));
            if (pending.Count >= 100) throw new VaultFault(429, "rate_limited");
            var token = Wire.NewToken();
            pending.Add(Wire.HashToken(token), new(admin, state, PublicOrigin(context), enroll, replace, store.Mfa.Passkeys.Length == 0, now.AddMinutes(2)));
            context.Response.Cookies.Append(Cookie, token, new() { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict, Path = "/admin", MaxAge = TimeSpan.FromMinutes(2) });
        }
        return new(false, enroll ? "register" : "verify", System.Text.Json.JsonSerializer.Deserialize(json, Wire.TypeInfo<System.Text.Json.JsonElement>()));
    }

    public async Task<VerifyResult> Verify(HttpContext context, VaultStore store, AdminSessions sessions, VerifyRequest input) {
        Challenge challenge;
        lock (gate) {
            if (context.Request.Cookies[Cookie] is not { } token || !pending.Remove(Wire.HashToken(token), out var found) || found.Expires <= clock.GetUtcNow()) throw new VaultFault(401, "unauthorized");
            challenge = found;
        }
        context.Response.Cookies.Delete(Cookie, new() { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict, Path = "/admin" });
        if (challenge.Origin != PublicOrigin(context) || context.Request.Headers.Origin != challenge.Origin) throw new VaultFault(401, "unauthorized");
        var credential = input.Credential.GetRawText();
        if (credential.Length > 32768) throw new VaultFault(400, "invalid_request");
        var handler = context.RequestServices.GetRequiredService<IPasskeyHandler<VaultStore.Admin>>();
        var audit = RequestAudit.Get(context);
        VaultStore.Admin admin; string[] codes = [];
        if (challenge.Enroll) {
            var result = await handler.PerformAttestationAsync(new() { HttpContext = context, CredentialJson = credential, AttestationState = challenge.State });
            if (!result.Succeeded || result.UserEntity.Id != challenge.Admin.Id) throw new VaultFault(401, "unauthorized");
            (admin, codes) = store.RegisterPasskey(challenge.Admin, result.Passkey, challenge.Replace, challenge.First, audit);
            sessions.Clear();
        } else {
            var result = await handler.PerformAssertionAsync(new() { HttpContext = context, CredentialJson = credential, AssertionState = challenge.State });
            if (!result.Succeeded || result.User.Id != challenge.Admin.Id) throw new VaultFault(401, "unauthorized");
            admin = store.CompletePasskey(challenge.Admin, result.Passkey, audit);
        }
        audit.Identify(new(admin.Id, true)); sessions.Create(context, admin);
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("DarkVault.Security").LogInformation(
            new EventId(3002), "DARKVAULT_ADMIN_AUTH method={Method} trace_id={TraceId}", challenge.Enroll ? "register" : "passkey", audit.TraceId);
        return new(true, codes);
    }

    public static void Map(WebApplication app, ILogger securityLog) {
        app.MapPost("/admin/mfa/options", async (HttpContext c, VaultStore store, AdminSessions sessions, AdminMfa mfa, IAntiforgery csrf) => {
            if (!await csrf.IsRequestValidAsync(c)) throw new VaultFault(400, "csrf_failed");
            var admin = sessions.Get(c, store) ?? throw new VaultFault(401, "unauthorized");
            await ServerJson.Write(c, await mfa.Begin(c, store, admin, false));
        });
        app.MapPost("/admin/mfa/register", async (HttpContext c, VaultStore store, AdminSessions sessions, AdminMfa mfa, IAntiforgery csrf) => {
            if (!await csrf.IsRequestValidAsync(c)) throw new VaultFault(400, "csrf_failed");
            var admin = sessions.Get(c, store) ?? throw new VaultFault(401, "unauthorized");
            sessions.RequireRecent(c); await ServerJson.Write(c, await mfa.Begin(c, store, admin, true));
        });
        app.MapPost("/admin/mfa/verify", async (HttpContext c, VaultStore store, AdminSessions sessions, AdminMfa mfa, IAntiforgery csrf, AbuseProtection abuse) => {
            if (!await csrf.IsRequestValidAsync(c)) throw new VaultFault(400, "csrf_failed");
            var input = ServerJson.Parse<VerifyRequest>(await Wire.ReadBodyAsync(c.Request.Body, c.RequestAborted));
            try { await ServerJson.Write(c, await mfa.Verify(c, store, sessions, input)); } catch (VaultFault ex) when (ex.Status == 401) {
                abuse.Failed(c.Connection.RemoteIpAddress, true);
                VaultApplication.AuthenticationFailed(c, securityLog, "mfa"); throw;
            }
        });
    }
}
