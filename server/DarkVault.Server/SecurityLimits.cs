using System.Net;
using System.Threading.RateLimiting;

namespace DarkVault.Server;

public sealed class SecurityLimits : IDisposable {
    public PartitionedRateLimiter<HttpContext> Network { get; }
    public PartitionedRateLimiter<string> Principals { get; }
    public PartitionedRateLimiter<string> Logins { get; }
    public PartitionedRateLimiter<string> Mfa { get; }
    public RateLimiter Passwords { get; }
    public SemaphoreSlim PasswordConcurrency { get; } = new(2);

    public SecurityLimits(IConfiguration configuration) {
        int Limit(string name, int fallback) {
            var text = configuration["Security:RateLimits:" + name];
            var value = text is null ? fallback : int.TryParse(text, out var parsed) ? parsed : 0;
            return value is > 0 and <= 100000 ? value : throw new InvalidOperationException("Invalid security rate limit: " + name);
        }
        var global = Limit("Global", 3000);
        var ip = Limit("Ip", 300);
        var principal = Limit("Principal", 300);
        var login = Limit("Login", 5);
        var password = Limit("Password", 30);
        var mfa = Limit("Mfa", 20);
        // Global admission precedes attacker-controlled partitions. The built-in limiter
        // replenishes and evicts idle partitions, bounding creation to the global budget.
        Network = PartitionedRateLimiter.CreateChained(
            PartitionedRateLimiter.Create<HttpContext, string>(_ => Window("global", global)),
            PartitionedRateLimiter.Create<HttpContext, string>(c => Window(AddressKey(c.Connection.RemoteIpAddress), ip)));
        Principals = PartitionedRateLimiter.Create<string, string>(id => Window(id, principal));
        Logins = PartitionedRateLimiter.Create<string, string>(ipKey => Window(ipKey, login));
        Mfa = PartitionedRateLimiter.Create<string, string>(ipKey => Window(ipKey, mfa));
        Passwords = new FixedWindowRateLimiter(new() { PermitLimit = password, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
    }

    private static RateLimitPartition<string> Window(string key, int limit) => RateLimitPartition.GetFixedWindowLimiter(key,
        _ => new FixedWindowRateLimiterOptions { PermitLimit = limit, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });

    public static string AddressKey(IPAddress? address) {
        if (address is null) return "unknown";
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6) return address.ToString();
        // Treat temporary addresses in one IPv6 /64 as one source.
        var bytes = address.GetAddressBytes(); Array.Clear(bytes, 8, 8);
        return new IPAddress(bytes).ToString();
    }

    public static int RetryAfter(RateLimitLease lease) => lease.TryGetMetadata(MetadataName.RetryAfter, out var delay)
        ? Math.Max(1, (int)Math.Ceiling(delay.TotalSeconds)) : 1;

    public void Dispose() {
        Network.Dispose(); Principals.Dispose(); Logins.Dispose(); Mfa.Dispose(); Passwords.Dispose(); PasswordConcurrency.Dispose();
    }
}
