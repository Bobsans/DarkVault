using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.RateLimiting;
using DarkVault.Client;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.DataProtection;

namespace DarkVault.Server;

public static class VaultApplication {
    public static WebApplication Build(string[] args, VaultStore store, KeyRing ring, string keyDirectory) {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions {
            Args = args,
            ApplicationName = typeof(VaultApplication).Assembly.FullName,
            ContentRootPath = AppContext.BaseDirectory
        });
        builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
        builder.WebHost.ConfigureKestrel(o => { o.Limits.MaxRequestBodySize = Wire.MaxBody; o.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10); });
        builder.Services.AddSingleton(store); builder.Services.AddSingleton(ring);
        builder.Services.AddSingleton<AdminSessions>();
        builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keyDirectory));
        builder.Services.AddAntiforgery(o => { o.HeaderName = "X-CSRF-Token"; o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.SameSite = SameSiteMode.Strict; });
        builder.Services.Configure<ForwardedHeadersOptions>(o => {
            o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            o.KnownIPNetworks.Clear(); o.KnownProxies.Clear();
            foreach (var proxy in (Environment.GetEnvironmentVariable("DARKVAULT_TRUSTED_PROXIES") ?? "127.0.0.1,::1").Split(',', StringSplitOptions.RemoveEmptyEntries)) o.KnownProxies.Add(IPAddress.Parse(proxy));
            o.ForwardLimit = 1;
        });
        builder.Services.AddRateLimiter(o => {
            o.RejectionStatusCode = 429;
            o.OnRejected = async (c, ct) => { c.HttpContext.Response.Headers.RetryAfter = "60"; await Error(c.HttpContext, 429, "rate_limited"); };
            o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(c => RateLimitPartition.GetFixedWindowLimiter("global", _ =>
                new FixedWindowRateLimiterOptions { PermitLimit = 3000, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
            o.AddPolicy("login", c => RateLimitPartition.GetFixedWindowLimiter("admin", _ =>
                new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
            o.AddPolicy("api", c => RateLimitPartition.GetFixedWindowLimiter(c.Connection.RemoteIpAddress?.ToString() ?? "unknown", _ =>
                new FixedWindowRateLimiterOptions { PermitLimit = 300, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
        });
        var app = builder.Build(); app.UseForwardedHeaders();
        app.Use(async (c, next) => {
            c.Response.Headers.CacheControl = "no-store"; c.Response.Headers.XContentTypeOptions = "nosniff";
            c.Response.Headers["Referrer-Policy"] = "no-referrer";
            c.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
            if (!c.Request.IsHttps && c.Request.Path != "/health/ready") { await Error(c, 400, "https_required"); return; }
            if (c.Request.IsHttps) c.Response.Headers.StrictTransportSecurity = "max-age=31536000";
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(c.RequestAborted); timeout.CancelAfter(TimeSpan.FromSeconds(30)); c.RequestAborted = timeout.Token;
            try { await next(c); } catch (OperationCanceledException) { if (!c.Response.HasStarted) await Error(c, 503, "unavailable"); } catch (VaultFault ex) { if (!c.Response.HasStarted) await Error(c, ex.Status, ex.Code); } catch (BadHttpRequestException ex) when (ex.StatusCode == 413) { if (!c.Response.HasStarted) await Error(c, 413, "payload_too_large"); } catch (InvalidDataException) { if (!c.Response.HasStarted) await Error(c, 413, "payload_too_large"); } catch (Exception ex) when (ex is JsonException or FormatException or KeyNotFoundException or InvalidOperationException or ArgumentException) { if (!c.Response.HasStarted) await Error(c, 400, "invalid_request"); } catch (Exception) { if (!c.Response.HasStarted) await Error(c, 503, "unavailable"); }
        });
        app.UseRateLimiter(); app.UseDefaultFiles(); app.UseStaticFiles();
        app.MapGet("/health/ready", () => { store.Ready(); return Results.Json(new HealthResult("ready"), ServerJson.TypeInfo<HealthResult>()); });
        app.MapGet("/api/v1/crypto/key", () => Results.Json(ring.Public(), ServerJson.TypeInfo<CryptoKey>())).RequireRateLimiting("api");
        app.MapGet("/admin/api/v1/session", (HttpContext c, IAntiforgery csrf, AdminSessions sessions) => Results.Json(new SessionResult(sessions.Get(c, store) is not null, csrf.GetAndStoreTokens(c).RequestToken), ServerJson.TypeInfo<SessionResult>()));
        app.MapPost("/admin/login", async (HttpContext c, IAntiforgery csrf, AdminSessions sessions) => {
            if (!await csrf.IsRequestValidAsync(c)) { await Error(c, 400, "csrf_failed"); return; }
            var credentials = ServerJson.Parse<LoginRequest>(await Wire.ReadBodyAsync(c.Request.Body, c.RequestAborted));
            var admin = credentials.Username == "admin" ? store.Login(credentials.Password) : null;
            if (admin is null) { store.RecordFailure("anonymous", "admin.login", "unauthorized"); await Error(c, 401, "unauthorized"); return; }
            sessions.Create(c, admin); await ServerJson.Write(c, new AuthenticationResult(true));
        }).RequireRateLimiting("login");
        app.MapPost("/admin/logout", async (HttpContext c, IAntiforgery csrf, AdminSessions sessions) => {
            if (!await csrf.IsRequestValidAsync(c)) { await Error(c, 400, "csrf_failed"); return; }
            sessions.Remove(c); await ServerJson.Write(c, new AuthenticationResult(false));
        });
        app.MapPost("/admin/password", async (HttpContext c, IAntiforgery csrf, AdminSessions sessions) => {
            if (!await csrf.IsRequestValidAsync(c)) { await Error(c, 400, "csrf_failed"); return; }
            if (sessions.Get(c, store) is null) throw new VaultFault(401, "unauthorized");
            var input = ServerJson.Parse<PasswordRequest>(await Wire.ReadBodyAsync(c.Request.Body, c.RequestAborted));
            if (store.Login(input.CurrentPassword) is null) throw new VaultFault(401, "unauthorized");
            store.SetPassword(input.NewPassword, true); sessions.Clear(); sessions.Remove(c); await ServerJson.Write(c, new PasswordResult(true));
        }).RequireRateLimiting("login");
        var admission = new SemaphoreSlim(64); app.Lifetime.ApplicationStopped.Register(admission.Dispose);
        app.MapPost("/api/v1/execute", (HttpContext c, AdminSessions sessions, IAntiforgery csrf) => Execute(c, false, store, ring, sessions, csrf, admission)).RequireRateLimiting("api");
        app.MapPost("/admin/api/v1/execute", (HttpContext c, AdminSessions sessions, IAntiforgery csrf) => Execute(c, true, store, ring, sessions, csrf, admission)).RequireRateLimiting("api");
        return app;
    }
    private static async Task Execute(HttpContext c, bool admin, VaultStore store, KeyRing ring, AdminSessions sessions, IAntiforgery csrf, SemaphoreSlim admission) {
        if (!await admission.WaitAsync(0, c.RequestAborted)) { await Error(c, 503, "unavailable"); return; }
        var principalId = "anonymous";
        try {
            if (c.Request.ContentLength > Wire.MaxBody) throw new VaultFault(413, "payload_too_large");
            VaultStore.Principal principal;
            if (admin) {
                if (!await csrf.IsRequestValidAsync(c)) throw new VaultFault(400, "csrf_failed");
                var account = sessions.Get(c, store) ?? throw new VaultFault(401, "unauthorized"); principal = new(account.Id, true);
            } else {
                var auth = c.Request.Headers.Authorization.ToString(); principal = store.Authenticate(auth.StartsWith("Bearer ", StringComparison.Ordinal) ? auth[7..] : "");
            }
            principalId = principal.Id;
            if (c.Request.ContentType?.Split(';')[0] != "application/jose") throw new VaultFault(400, "invalid_envelope");
            VaultRequest request;
            try { request = ServerJson.Parse<VaultRequest>(ring.DecryptRequest(await Wire.ReadBodyAsync(c.Request.Body, c.RequestAborted))); using var reply = Wire.Import(request.ReplyKey); } catch (VaultFault) { throw; } catch (Exception ex) when (ex is FormatException or JsonException or CryptographicException or Jose.JoseException or ArgumentException or KeyNotFoundException or InvalidOperationException) { throw new VaultFault(400, "invalid_envelope"); }
            object? data = null; VaultError? error = null; var status = request.Operation is "bucket.create" or "secret.create" or "token.create" ? 201 : 200;
            var dispatched = false;
            try {
                if (request.V != 1) throw new VaultFault(400, "unsupported_version");
                if (request.Operation is null || request.Operation.Length > 64 || request.Operation.Any(ch => !char.IsAsciiLetter(ch) && ch != '.') || request.Parameters.ValueKind != JsonValueKind.Object)
                    throw new VaultFault(400, "invalid_request");
                if (request.ServerId != ring.ServerId || request.Audience != (admin ? "admin" : "data") || !Guid.TryParseExact(request.RequestId, "D", out var id) || id.Version != 4 || request.IssuedAt.Offset != TimeSpan.Zero) throw new VaultFault(400, "invalid_request");
                var age = DateTimeOffset.UtcNow - request.IssuedAt;
                if (age.TotalSeconds > 60 || age.TotalSeconds < -30) throw new VaultFault(400, "request_expired");
                store.Reserve(principal, request); dispatched = true; data = store.Run(principal, request.Operation, request.Parameters, request.RequestId, c.RequestAborted);
            } catch (VaultFault ex) {
                if (!dispatched) store.RecordFailure(principalId, "execute", ex.Code);
                status = ex.Status; error = new(ex.Code, "Request rejected.");
            } catch (Exception) { status = 503; error = new("unavailable", "Request could not be completed."); }
            var response = new VaultResponse(1, request.RequestId, ring.ServerId, admin ? "admin" : "data", request.Operation, status, data is null ? null : ServerJson.ToElement(data), error);
            var encrypted = Wire.Encrypt(ServerJson.Serialize(response), request.ReplyKey, request.RequestId, "darkvault-response+jwe");
            c.Response.StatusCode = status; c.Response.ContentType = "application/jose"; await c.Response.WriteAsync(encrypted, c.RequestAborted);
        } catch (VaultFault ex) {
            store.RecordFailure(principalId, "execute", ex.Code); throw;
        } finally { admission.Release(); }
    }
    private static Task Error(HttpContext c, int status, string code) { c.Response.StatusCode = status; return ServerJson.Write(c, new ErrorResult(new VaultError(code, "Request rejected."))); }
    public sealed record LoginRequest(string Username, string Password);
    public sealed record PasswordRequest(string CurrentPassword, string NewPassword);
}
public sealed class AdminSessions {
    private const string Cookie = "__Host-DarkVault";
    private readonly ConcurrentDictionary<string, Session> sessions = new();
    public void Create(HttpContext c, VaultStore.Admin admin) {
        Remove(c);
        foreach (var (key, session) in sessions) if (session.Created < DateTimeOffset.UtcNow.AddHours(-12) || session.Last < DateTimeOffset.UtcNow.AddMinutes(-30)) sessions.TryRemove(key, out _);
        if (sessions.Count >= 100) throw new VaultFault(429, "rate_limited");
        var token = Wire.NewToken(); var now = DateTimeOffset.UtcNow; sessions[Wire.HashToken(token)] = new(admin.Stamp, now, now);
        c.Response.Cookies.Append(Cookie, token, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/", MaxAge = TimeSpan.FromHours(12) });
    }
    public VaultStore.Admin? Get(HttpContext c, VaultStore store) {
        var value = c.Request.Cookies[Cookie]; if (value is null || !Wire.IsToken(value)) return null;
        var key = Wire.HashToken(value); if (!sessions.TryGetValue(key, out var s)) return null;
        var now = DateTimeOffset.UtcNow; var admin = store.Administrator;
        if (s.Created.AddHours(12) <= now || s.Last.AddMinutes(30) <= now || admin?.Stamp != s.Stamp) { sessions.TryRemove(key, out _); return null; }
        sessions.TryUpdate(key, s with { Last = now }, s); return admin;
    }
    public void Clear() => sessions.Clear();
    public void Remove(HttpContext c) {
        if (c.Request.Cookies[Cookie] is string token && Wire.IsToken(token)) sessions.TryRemove(Wire.HashToken(token), out _);
        c.Response.Cookies.Delete(Cookie, new CookieOptions { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict, Path = "/" });
    }
    private sealed record Session(string Stamp, DateTimeOffset Created, DateTimeOffset Last);
}
