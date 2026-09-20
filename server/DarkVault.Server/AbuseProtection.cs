using System.Net;

namespace DarkVault.Server;

// Process-local protection: no firewall, proxy or external service is required.
public sealed class AbuseProtection(TimeProvider clock) {
    public const int Capacity = 8192;
    private readonly object gate = new();
    private readonly Dictionary<string, Attempts> sources = new();
    private DateTimeOffset nextCleanup;

    public int RetryAfter(IPAddress? address) {
        lock (gate) {
            var now = clock.GetUtcNow(); Cleanup(now);
            if (sources.TryGetValue(SecurityLimits.AddressKey(address), out var state))
                return Math.Max(0, (int)Math.Ceiling((state.BlockedUntil - now).TotalSeconds));
            // Do not evict live bans to make room for attacker-controlled source addresses.
            return sources.Count >= Capacity ? 60 : 0;
        }
    }

    public void Failed(IPAddress? address, bool password) {
        lock (gate) {
            var now = clock.GetUtcNow(); Cleanup(now);
            var key = SecurityLimits.AddressKey(address);
            if (!sources.TryGetValue(key, out var state)) {
                if (sources.Count >= Capacity) return;
                sources.Add(key, state = new Attempts { Window = now });
            }
            if (state.BlockedUntil > now) return;
            if (now - state.Window >= TimeSpan.FromMinutes(10)) { state.Window = now; state.Login = 0; state.Api = 0; }
            state.Last = now;
            if (password) state.Login++; else state.Api++;
            if (state.Login < 10 && state.Api < 60) return;
            state.Strikes = Math.Min(state.Strikes + 1, 8);
            state.BlockedUntil = now.AddMinutes(Math.Min(15 * (1 << (state.Strikes - 1)), 1440));
            state.Window = now; state.Login = 0; state.Api = 0;
        }
    }

    private void Cleanup(DateTimeOffset now) {
        if (now < nextCleanup) return;
        foreach (var key in sources.Where(p => p.Value.BlockedUntil <= now && p.Value.Last.AddDays(1) <= now).Select(p => p.Key).ToArray()) sources.Remove(key);
        nextCleanup = now.AddMinutes(1);
    }

    private sealed class Attempts {
        public DateTimeOffset Window, Last, BlockedUntil;
        public int Login, Api, Strikes;
    }
}
