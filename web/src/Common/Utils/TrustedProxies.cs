using System.Net;

namespace VulWall.Dashboard.Common.Utils;

/// <summary>
/// Parses the TRUSTED_PROXIES setting: a comma-separated list of IP addresses or CIDR ranges
/// whose X-Forwarded-For / X-Forwarded-Proto headers are honored.
/// </summary>
public static class TrustedProxies
{
    /// <summary>
    /// Returns the configured networks. A bare address becomes a single-host network (/32 or /128).
    /// Throws <see cref="FormatException"/> on an invalid entry so a typo fails startup instead of
    /// silently trusting nothing (or everything).
    /// </summary>
    public static IReadOnlyList<IPNetwork> Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return [];

        var networks = new List<IPNetwork>();
        foreach (var raw in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (raw.Contains('/'))
            {
                if (!IPNetwork.TryParse(raw, out var network))
                    throw new FormatException($"TRUSTED_PROXIES: '{raw}' is not a valid CIDR range.");
                networks.Add(network);
                continue;
            }

            if (!IPAddress.TryParse(raw, out var address))
                throw new FormatException($"TRUSTED_PROXIES: '{raw}' is not a valid IP address.");
            var prefix = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
            networks.Add(new IPNetwork(address, prefix));
        }

        return networks;
    }
}
