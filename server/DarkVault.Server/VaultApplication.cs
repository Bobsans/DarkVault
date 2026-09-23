using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Http.Features;
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
        builder.Logging.AddSimpleConsole(o => { o.SingleLine = true; o.IncludeScopes = false; o.UseUtcTimestamp = true; o.TimestampFormat = "yyyy-MM-ddTHH:mm:ssZ "; });
        builder.WebHost.ConfigureKestrel(o => {
            o.Limits.MaxRequestBodySize = Wire.MaxBody; o.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(10);
            o.Limits.MaxRequestHeadersTotalSize = 16 * 1024; o.Limits.MaxRequestHeaderCount = 64;
            o.Limits.MaxConcurrentConnections = 256;
        });
        if (builder.Configuration["Audit:RetentionDays"] is { } retention)
            store.AuditRetention = int.TryParse(retention, System.Globalization.CultureInfo.InvariantCulture, out var days) && days is >= 1 and <= 3650
                ? TimeSpan.FromDays(days) : throw new InvalidOperationException("Audit:RetentionDays must be an integer from 1 to 3650.");
        builder.Services.AddSingleton(store); builder.Services.AddSingleton(ring);
        builder.Services.AddSingleton<AdminSessions>();
        builder.Services.AddSingleton<SecurityLimits>();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<AbuseProtection>();
        AdminMfa.Configure(builder);
        builder.Services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(keyDirectory));
        builder.Services.AddAntiforgery(o => { o.HeaderName = "X-CSRF-Token"; o.Cookie.SecurePolicy = CookieSecurePolicy.Always; o.Cookie.SameSite = SameSiteMode.Strict; });
        builder.Services.Configure<ForwardedHeadersOptions>(o => {
            o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            o.KnownIPNetworks.Clear(); o.KnownProxies.Clear();
            foreach (var proxy in (builder.Configuration["DARKVAULT_TRUSTED_PROXIES"] ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) {
                var address = IPAddress.Parse(proxy); o.KnownProxies.Add(address);
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) o.KnownProxies.Add(address.MapToIPv6());
            }
            o.ForwardLimit = 1;
        });
        var app = builder.Build();
        var limits = app.Services.GetRequiredService<SecurityLimits>();
        var abuse = app.Services.GetRequiredService<AbuseProtection>();
        var securityLog = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("DarkVault.Security");
        app.Use(async (c, next) => {
            var audit = new RequestAudit {
                PeerIp = c.Connection.RemoteIpAddress?.ToString(),
                Method = c.Request.Method,
                Path = c.Request.Path.Value is { } path ? path[..Math.Min(path.Length, 2048)] : null,
                Operation = c.Request.Path.Value switch {
                    "/admin/login" => "admin.login",
                    "/admin/logout" => "admin.logout",
                    "/admin/password" => "admin.password",
                    "/admin/mfa/options" => "admin.mfa.options",
                    "/admin/mfa/register" => "admin.mfa.register",
                    "/admin/mfa/verify" => "admin.mfa.verify",
                    "/admin/api/v1/session" => "admin.session",
                    "/api/v1/crypto/key" => "crypto.key",
                    "/health/ready" => "health.ready",
                    "/api/v1/execute" or "/admin/api/v1/execute" => "execute",
                    _ => "http.request"
                }
            };
            RequestAudit.Attach(c, audit);
            c.Response.OnStarting(() => { c.Response.Headers["X-Request-Id"] = audit.TraceId; return Task.CompletedTask; });
            try { await next(c); } finally {
                if (c.RequestAborted.IsCancellationRequested) audit.Error ??= "request_aborted";
                var entry = audit.Complete(c.Response.StatusCode);
                // Anonymous traffic and throttled requests must not write to the vault database.
                // Authentication failures are emitted once, at their validation boundary below.
                try { if (audit.Actor is not null && c.Response.StatusCode != 429) store.RecordRequest(entry); } catch (Exception) {
                    // Do not expose exception messages, SQL, credentials, or request bodies.
                    app.Logger.LogError("HTTP audit persistence failed. Audit={Audit}", ServerJson.Serialize(entry));
                    if (!c.Response.HasStarted) await Error(c, 503, "audit_unavailable");
                }
            }
        });
        // Empty KnownProxies/Networks means trust everyone in ForwardedHeadersMiddleware.
        // Do not enable the middleware at all until the operator explicitly names proxies.
        if (!string.IsNullOrWhiteSpace(builder.Configuration["DARKVAULT_TRUSTED_PROXIES"])) app.UseForwardedHeaders();
        app.Use(async (c, next) => {
            var audit = RequestAudit.Get(c); audit.SourceIp = c.Connection.RemoteIpAddress?.ToString();
            c.Response.Headers.CacheControl = "no-store"; c.Response.Headers.XContentTypeOptions = "nosniff";
            c.Response.Headers["Referrer-Policy"] = "no-referrer";
            c.Response.Headers.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
            if (!c.Request.IsHttps && c.Request.Path != "/health/ready" && !LocalMetrics(c)) { await Error(c, 400, "https_required"); return; }
            if (c.Request.IsHttps) c.Response.Headers.StrictTransportSecurity = "max-age=31536000";
            using var networkLease = limits.Network.AttemptAcquire(c);
            if (!networkLease.IsAcquired) { await RateLimited(c, networkLease); return; }
            var blockedFor = abuse.RetryAfter(c.Connection.RemoteIpAddress);
            if (blockedFor > 0) { c.Response.Headers.RetryAfter = blockedFor.ToString(System.Globalization.CultureInfo.InvariantCulture); await Error(c, 429, "rate_limited"); return; }
            if (c.Request.Path == "/admin/login" || c.Request.Path == "/admin/password" || c.Request.Path.StartsWithSegments("/admin/mfa")) {
                using var loginLease = (c.Request.Path.StartsWithSegments("/admin/mfa") ? limits.Mfa : limits.Logins).AttemptAcquire(SecurityLimits.AddressKey(c.Connection.RemoteIpAddress));
                if (!loginLease.IsAcquired) { await RateLimited(c, loginLease); return; }
            }
            var adminBody = c.Request.Path == "/admin/login" || c.Request.Path == "/admin/password" || c.Request.Path.StartsWithSegments("/admin/mfa");
            if (adminBody && c.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } bodySize) bodySize.MaxRequestBodySize = 64 * 1024;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(c.RequestAborted); timeout.CancelAfter(TimeSpan.FromSeconds(30)); c.RequestAborted = timeout.Token;
            try {
                var invalidBearer = false;
                if (c.Request.Path == "/api/v1/execute") {
                    var auth = c.Request.Headers.Authorization.ToString();
                    try { audit.Identify(store.Authenticate(auth.StartsWith("Bearer ", StringComparison.Ordinal) ? auth[7..] : "")); } catch (VaultFault) { abuse.Failed(c.Connection.RemoteIpAddress, false); AuthenticationFailed(c, securityLog, "api"); invalidBearer = true; }
                } else if (c.RequestServices.GetRequiredService<AdminSessions>().Get(c, store) is { } admin) audit.Identify(new(admin.Id, true));
                if (c.Request.Path != "/health/ready") {
                    using var globalLease = (audit.Actor is null ? limits.AnonymousRequests : limits.AuthenticatedRequests).AttemptAcquire();
                    if (!globalLease.IsAcquired) { await RateLimited(c, globalLease); return; }
                }
                if (invalidBearer) { await Error(c, 401, "unauthorized"); return; }
                if (audit.Actor is { } actor) {
                    using var principalLease = limits.Principals.AttemptAcquire((actor.IsAdmin ? "admin:" : "token:") + actor.Id);
                    if (!principalLease.IsAcquired) { await RateLimited(c, principalLease); return; }
                }
                await next(c);
            } catch (OperationCanceledException) { await Failure(c, 503, "unavailable"); } catch (VaultFault ex) { await Failure(c, ex.Status, ex.Code); } catch (BadHttpRequestException ex) when (ex.StatusCode == 413) { await Failure(c, 413, "payload_too_large"); } catch (InvalidDataException) { await Failure(c, 413, "payload_too_large"); } catch (Exception ex) { app.Logger.LogError("Unhandled request failure. TraceId={TraceId} Type={ExceptionType}", RequestAudit.Get(c).TraceId, ex.GetType().Name); await Failure(c, 503, "unavailable"); }
        });
        app.UseDefaultFiles(); app.UseStaticFiles();
        // Only UI routes receive the SPA shell; unknown API and asset paths remain 404.
        var shell = Path.Combine(app.Environment.WebRootPath ?? Path.Combine(AppContext.BaseDirectory, "wwwroot"), "index.html");
        foreach (var route in new[] { "/admin", "/admin/buckets", "/admin/tokens", "/admin/logs", "/admin/settings" })
            app.MapGet(route, () => Results.File(shell, "text/html; charset=utf-8"));
        app.MapGet("/admin/buckets/{name}", (string name) =>
            System.Text.RegularExpressions.Regex.IsMatch(name, @"\A[a-z0-9][a-z0-9_-]{0,62}\z", System.Text.RegularExpressions.RegexOptions.CultureInvariant)
                ? (IResult)Results.File(shell, "text/html; charset=utf-8") : Results.NotFound());
        app.MapGet("/health/ready", () => { store.Ready(); return Results.Json(new HealthResult("ready"), ServerJson.TypeInfo<HealthResult>()); });
        app.MapGet("/metrics", (HttpContext c) => LocalMetrics(c) ? Results.Text(RequestAudit.PrometheusMetrics(), "text/plain; version=0.0.4; charset=utf-8") : Results.NotFound());
        app.MapGet("/api/v1/crypto/key", () => Results.Json(ring.Public(), ServerJson.TypeInfo<CryptoKey>()));
        app.MapGet("/admin/api/v1/session", (HttpContext c, IAntiforgery csrf, AdminSessions sessions) => { var authenticated = sessions.Get(c, store) is not null; return Results.Json(new SessionResult(authenticated, csrf.GetAndStoreTokens(c).RequestToken, authenticated ? ServerCommands.InformationalVersion : null), ServerJson.TypeInfo<SessionResult>()); });
        app.MapPost("/admin/login", async (HttpContext c, IAntiforgery csrf, AdminSessions sessions, AdminMfa mfa) => {
            if (!await csrf.IsRequestValidAsync(c)) { await Error(c, 400, "csrf_failed"); return; }
            var credentials = await ReadRequest<LoginRequest>(c);
            var admin = await CheckPassword(c, store, limits, credentials.Password);
            if (c.Response.StatusCode == 429) return;
            if (credentials.Username != "admin" || admin is null) { abuse.Failed(c.Connection.RemoteIpAddress, true); AuthenticationFailed(c, securityLog, "login"); await Error(c, 401, "unauthorized"); return; }
            var recover = !string.IsNullOrEmpty(credentials.RecoveryCode);
            if (recover) {
                try { admin = store.ConsumeRecovery(admin, credentials.RecoveryCode!, RequestAudit.Get(c)); sessions.Clear(); } catch (VaultFault) { abuse.Failed(c.Connection.RemoteIpAddress, true); AuthenticationFailed(c, securityLog, "recovery"); throw; }
            }
            sessions.Remove(c);
            await ServerJson.Write(c, await mfa.Begin(c, store, admin, recover || store.Mfa.Passkeys.Length == 0, recover));
        });
        app.MapPost("/admin/logout", async (HttpContext c, IAntiforgery csrf, AdminSessions sessions) => {
            if (!await csrf.IsRequestValidAsync(c)) { await Error(c, 400, "csrf_failed"); return; }
            _ = sessions.Get(c, store); sessions.Remove(c); await ServerJson.Write(c, new AuthenticationResult(false));
        });
        app.MapPost("/admin/password", async (HttpContext c, IAntiforgery csrf, AdminSessions sessions) => {
            if (!await csrf.IsRequestValidAsync(c)) { await Error(c, 400, "csrf_failed"); return; }
            if (sessions.Get(c, store) is null) throw new VaultFault(401, "unauthorized");
            sessions.RequireRecent(c);
            var input = await ReadRequest<PasswordRequest>(c);
            var admin = await CheckPassword(c, store, limits, input.CurrentPassword);
            if (c.Response.StatusCode == 429) return;
            if (admin is null) { abuse.Failed(c.Connection.RemoteIpAddress, true); AuthenticationFailed(c, securityLog, "login"); throw new VaultFault(401, "unauthorized"); }
            store.SetPassword(input.NewPassword, true, RequestAudit.Get(c)); sessions.Clear(); sessions.Remove(c); await ServerJson.Write(c, new PasswordResult(true));
        });
        var admission = new SemaphoreSlim(64); app.Lifetime.ApplicationStopped.Register(admission.Dispose);
        app.MapPost("/api/v1/execute", (HttpContext c, AdminSessions sessions, IAntiforgery csrf) => Execute(c, false, store, ring, sessions, csrf, admission));
        app.MapPost("/admin/api/v1/execute", (HttpContext c, AdminSessions sessions, IAntiforgery csrf) => Execute(c, true, store, ring, sessions, csrf, admission));
        AdminMfa.Map(app, securityLog);
        return app;
    }
    private static async Task<VaultStore.Admin?> CheckPassword(HttpContext c, VaultStore store, SecurityLimits limits, string password) {
        using var budget = limits.Passwords.AttemptAcquire();
        if (!budget.IsAcquired) { await RateLimited(c, budget); return null; }
        if (!await limits.PasswordConcurrency.WaitAsync(0, c.RequestAborted)) {
            c.Response.Headers.RetryAfter = "1"; await Error(c, 429, "rate_limited"); return null;
        }
        try { return store.Login(password); } finally { limits.PasswordConcurrency.Release(); }
    }
    // Metrics are for a scraper on the same host. A loopback peer carrying forwarding headers
    // is a reverse proxy relaying a remote client, so it is refused as well.
    private static bool LocalMetrics(HttpContext c) =>
        c.Request.Path == "/metrics" && c.Connection.RemoteIpAddress is { } ip && IPAddress.IsLoopback(ip)
        && !c.Request.Headers.ContainsKey("X-Forwarded-For") && !c.Request.Headers.ContainsKey("X-Original-For")
        && !c.Request.Headers.ContainsKey("Forwarded");

    private static Task RateLimited(HttpContext c, RateLimitLease lease) {
        c.Response.Headers.RetryAfter = SecurityLimits.RetryAfter(lease).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return Error(c, 429, "rate_limited");
    }
    internal static void AuthenticationFailed(HttpContext c, ILogger logger, string kind) {
        var address = c.Connection.RemoteIpAddress;
        if (address is null) return;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        // Only server-generated fields; never include usernames, tokens, bodies or headers.
        logger.LogWarning(new EventId(3001), "DARKVAULT_AUTH_FAILURE kind={Kind} source_ip={SourceIp} trace_id={TraceId}",
            kind, address.ToString(), RequestAudit.Get(c).TraceId);
    }
    private static async Task Execute(HttpContext c, bool admin, VaultStore store, KeyRing ring, AdminSessions sessions, IAntiforgery csrf, SemaphoreSlim admission) {
        if (!await admission.WaitAsync(0, c.RequestAborted)) { await Error(c, 503, "unavailable"); return; }
        var audit = RequestAudit.Get(c);
        try {
            if (c.Request.ContentLength > Wire.MaxBody) throw new VaultFault(413, "payload_too_large");
            VaultStore.Principal principal;
            if (admin) {
                if (!await csrf.IsRequestValidAsync(c)) throw new VaultFault(400, "csrf_failed");
                var account = sessions.Get(c, store) ?? throw new VaultFault(401, "unauthorized"); principal = new(account.Id, true);
            } else {
                principal = audit.Actor ?? throw new VaultFault(401, "unauthorized");
            }
            audit.Identify(principal);
            if (c.Request.ContentType?.Split(';')[0] != "application/jose") throw new VaultFault(400, "invalid_envelope");
            VaultRequest request;
            try { request = ServerJson.Parse<VaultRequest>(ring.DecryptRequest(await Wire.ReadBodyAsync(c.Request.Body, c.RequestAborted))); using var reply = Wire.Import(request.ReplyKey); } catch (VaultFault) { throw; } catch (Exception ex) when (ex is FormatException or JsonException or CryptographicException or Jose.JoseException or ArgumentException or KeyNotFoundException or InvalidOperationException) { throw new VaultFault(400, "invalid_envelope"); }
            object? data = null; VaultError? error = null; var status = request.Operation is "bucket.create" or "secret.create" or "token.create" ? 201 : 200;
            try {
                if (request.V != 1) throw new VaultFault(400, "unsupported_version");
                if (request.Operation is null || request.Operation.Length > 64 || request.Operation.Any(ch => !char.IsAsciiLetter(ch) && ch != '.') || request.Parameters.ValueKind != JsonValueKind.Object)
                    throw new VaultFault(400, "invalid_request");
                if (request.ServerId != ring.ServerId || request.Audience != (admin ? "admin" : "data") || !Guid.TryParseExact(request.RequestId, "D", out var id) || id.Version != 4 || request.IssuedAt.Offset != TimeSpan.Zero) throw new VaultFault(400, "invalid_request");
                audit.Operation = request.Operation; audit.RequestId = request.RequestId;
                audit.Details = VaultStore.AuditParameters(request.Operation, request.Parameters);
                var age = DateTimeOffset.UtcNow - request.IssuedAt;
                if (age.TotalSeconds > 60 || age.TotalSeconds < -30) throw new VaultFault(400, "request_expired");
                if (admin && (request.Operation == "token.create" || request.Operation == "bucket.delete")) sessions.RequireRecent(c);
                store.Reserve(principal, request); data = store.Run(principal, request.Operation, request.Parameters, request.RequestId, c.RequestAborted, audit);
            } catch (VaultFault ex) {
                audit.Error = ex.Code;
                status = ex.Status; error = new(ex.Code, "Request rejected.");
            } catch (Exception) { audit.Error = "unavailable"; status = 503; error = new("unavailable", "Request could not be completed."); }
            var response = new VaultResponse(1, request.RequestId, ring.ServerId, admin ? "admin" : "data", request.Operation, status, data is null ? null : ServerJson.ToElement(data), error);
            var encrypted = Wire.Encrypt(ServerJson.Serialize(response), request.ReplyKey, request.RequestId, "darkvault-response+jwe");
            c.Response.StatusCode = status; c.Response.ContentType = "application/jose"; await c.Response.WriteAsync(encrypted, c.RequestAborted);
        } finally { admission.Release(); }
    }
    private static async Task<T> ReadRequest<T>(HttpContext c) {
        var body = await Wire.ReadBodyAsync(c.Request.Body, c.RequestAborted);
        try { return ServerJson.Parse<T>(body); } catch (Exception ex) when (ex is JsonException or FormatException or KeyNotFoundException or InvalidOperationException or ArgumentException) {
            throw new VaultFault(400, "invalid_request");
        }
    }
    private static Task Failure(HttpContext c, int status, string code) {
        RequestAudit.Get(c).Error = code;
        return c.Response.HasStarted ? Task.CompletedTask : Error(c, status, code);
    }
    private static Task Error(HttpContext c, int status, string code) { RequestAudit.Get(c).Error = code; c.Response.StatusCode = status; return ServerJson.Write(c, new ErrorResult(new VaultError(code, "Request rejected."))); }
    public sealed record LoginRequest(string Username, string Password, string? RecoveryCode = null);
    public sealed record PasswordRequest(string CurrentPassword, string NewPassword);
}
public sealed class AdminSessions {
    private const string Cookie = "__Secure-DarkVault";
    private readonly ConcurrentDictionary<string, Session> sessions = new();
    public void Create(HttpContext c, VaultStore.Admin admin) {
        Remove(c);
        foreach (var (key, session) in sessions) if (session.Created < DateTimeOffset.UtcNow.AddHours(-12) || session.Last < DateTimeOffset.UtcNow.AddMinutes(-30)) sessions.TryRemove(key, out _);
        if (sessions.Count >= 100) throw new VaultFault(429, "rate_limited");
        var token = Wire.NewToken(); var now = DateTimeOffset.UtcNow; sessions[Wire.HashToken(token)] = new(admin.Stamp, now, now);
        c.Response.Cookies.Append(Cookie, token, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/admin", MaxAge = TimeSpan.FromHours(12) });
    }
    public VaultStore.Admin? Get(HttpContext c, VaultStore store) {
        var value = c.Request.Cookies[Cookie]; if (value is null || !Wire.IsToken(value)) return null;
        var key = Wire.HashToken(value); if (!sessions.TryGetValue(key, out var s)) return null;
        var now = DateTimeOffset.UtcNow; var admin = store.Administrator;
        if (s.Created.AddHours(12) <= now || s.Last.AddMinutes(30) <= now || admin?.Stamp != s.Stamp) { sessions.TryRemove(key, out _); return null; }
        sessions.TryUpdate(key, s with { Last = now }, s);
        RequestAudit.Get(c).Identify(new(admin!.Id, true)); return admin;
    }
    public void Clear() => sessions.Clear();
    public void RequireRecent(HttpContext c) {
        if (c.Request.Cookies[Cookie] is not { } token || !sessions.TryGetValue(Wire.HashToken(token), out var session) || session.Created.AddMinutes(5) <= DateTimeOffset.UtcNow)
            throw new VaultFault(403, "reauth_required");
    }
    public void Remove(HttpContext c) {
        if (c.Request.Cookies[Cookie] is string token && Wire.IsToken(token)) sessions.TryRemove(Wire.HashToken(token), out _);
        c.Response.Cookies.Delete(Cookie, new CookieOptions { Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict, Path = "/admin" });
    }
    private sealed record Session(string Stamp, DateTimeOffset Created, DateTimeOffset Last);
}
