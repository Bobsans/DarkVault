using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace DarkVault.Server;

// Only allowlisted metadata belongs here; never attach request or response bodies.
public sealed class RequestAudit {
    private static readonly Meter Meter = new("DarkVault.Security");
    private static readonly Counter<long> Requests = Meter.CreateCounter<long>("darkvault.http.requests");
    private static long totalRequests;
    private static readonly object ItemKey = new();
    public static long TotalRequests => Interlocked.Read(ref totalRequests);
    public static string PrometheusMetrics() => "# HELP darkvault_http_requests_total Total HTTP requests.\n# TYPE darkvault_http_requests_total counter\ndarkvault_http_requests_total " + TotalRequests.ToString(System.Globalization.CultureInfo.InvariantCulture) + "\n";
    private readonly long started = Stopwatch.GetTimestamp();
    public DateTimeOffset StartedAt { get; } = DateTimeOffset.UtcNow;
    public string TraceId { get; } = Guid.NewGuid().ToString();
    public string Principal { get; private set; } = "anonymous";
    public string PrincipalType { get; private set; } = "anonymous";
    public string? PrincipalName { get; private set; }
    public string Operation { get; internal set; } = "http.request";
    public string? RequestId { get; internal set; }
    public string? Error { get; internal set; }
    public string? SourceIp { get; internal set; }
    public string? PeerIp { get; internal set; }
    public string? Method { get; internal set; }
    public string? Path { get; internal set; }
    public double DurationMs => Stopwatch.GetElapsedTime(started).TotalMilliseconds;
    internal VaultStore.Principal? Actor { get; private set; }
    internal AuditDetails? Details { get; set; }

    internal static RequestAudit Get(HttpContext context) => (RequestAudit)context.Items[ItemKey]!;
    internal static void Attach(HttpContext context, RequestAudit audit) => context.Items[ItemKey] = audit;
    internal AuditEntry Complete(int statusCode) {
        Interlocked.Increment(ref totalRequests);
        // Fixed-cardinality labels: never use paths, source IPs, token IDs or user input.
        Requests.Add(1, new KeyValuePair<string, object?>("status", statusCode), new("principal_type", PrincipalType));
        return new(DateTimeOffset.UtcNow, Principal, Operation, null, null,
            RequestId ?? TraceId, Error ?? (statusCode < 400 ? "success" : "http_error"),
            "http", PrincipalType, PrincipalName, TraceId, StartedAt, SourceIp, PeerIp, Method, Path, statusCode, DurationMs, Details);
    }
    internal void Identify(VaultStore.Principal principal) {
        Actor = principal;
        Principal = principal.Id;
        PrincipalType = principal.IsAdmin ? "admin" : "token";
        PrincipalName = principal.IsAdmin ? "admin" : principal.Token?.Name;
    }
}

internal sealed record AuditResource(string Kind, string Id, string Name, string? BucketId = null, long? Revision = null, string? Type = null);
internal sealed record AuditDetails(string? Bucket, string? Key, string? TokenId, long? ExpectedRevision,
    bool? Recursive, AuditResource[] Resources, int? ReturnedCount = null, StoredTokenInfo? Token = null);
