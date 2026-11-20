using System.Net;
using System.Net.Sockets;

namespace VulWall.Dashboard.Assets.Validation;

public static class PrivateIpValidator
{
    private static readonly (uint Network, uint Mask)[] ReservedIpv4Ranges =
    [
        // Loopback
        (IpToUint("127.0.0.0"), PrefixLengthToMask(8)),
        // RFC1918 private ranges
        (IpToUint("10.0.0.0"),  PrefixLengthToMask(8)),
        (IpToUint("172.16.0.0"), PrefixLengthToMask(12)),
        (IpToUint("192.168.0.0"), PrefixLengthToMask(16)),
        // Link-local / AWS metadata
        (IpToUint("169.254.0.0"), PrefixLengthToMask(16)),
        // CGNAT (RFC6598)
        (IpToUint("100.64.0.0"), PrefixLengthToMask(10)),
        // Unspecified
        (IpToUint("0.0.0.0"), PrefixLengthToMask(8)),
        // Documentation ranges
        (IpToUint("192.0.0.0"), PrefixLengthToMask(24)),
        (IpToUint("192.0.2.0"), PrefixLengthToMask(24)),
        (IpToUint("198.51.100.0"), PrefixLengthToMask(24)),
        (IpToUint("203.0.113.0"), PrefixLengthToMask(24)),
        // Benchmarking (RFC2544)
        (IpToUint("198.18.0.0"), PrefixLengthToMask(15)),
        // Multicast
        (IpToUint("224.0.0.0"), PrefixLengthToMask(4)),
        // Reserved (RFC1112)
        (IpToUint("240.0.0.0"), PrefixLengthToMask(4)),
    ];

    /// <summary>
    /// Returns true if the IP is private, reserved, or unparseable.
    /// Fails closed — an unparseable input is treated as private to prevent SSRF.
    /// </summary>
    public static bool IsPrivateIp(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var ip))
        {
            // Fail closed: unparseable input is rejected
            return true;
        }

        // Normalise IPv4-mapped IPv6 addresses (e.g. ::ffff:192.168.1.1)
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv4MappedToIPv6)
            {
                ip = ip.MapToIPv4();
            }
            else
            {
                return IsPrivateIpv6(ip);
            }
        }

        return IsPrivateIpv4(ip);
    }

    /// <summary>
    /// Resolves the domain and returns true if ANY resolved address is private.
    /// Returns false on resolution failure — the scanner will handle unreachable domains naturally.
    /// </summary>
    public static async Task<bool> DomainResolvesToPrivateIpAsync(string domain)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(domain);
            return addresses.Any(address => IsPrivateIp(address.ToString()));
        }
        catch (SocketException)
        {
            // Domain cannot be resolved — not a private IP issue, let the scanner handle it
            return false;
        }
    }

    private static bool IsPrivateIpv4(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        var ipUint = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        return ReservedIpv4Ranges.Any(range => (ipUint & range.Mask) == range.Network);
    }

    private static bool IsPrivateIpv6(IPAddress ip)
    {
        // Unspecified address ::
        if (ip.Equals(IPAddress.IPv6Any))
        {
            return true;
        }

        // Loopback ::1
        if (ip.Equals(IPAddress.IPv6Loopback))
        {
            return true;
        }

        var bytes = ip.GetAddressBytes();

        // Link-local fe80::/10 — first 10 bits are 1111 1110 10
        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
        {
            return true;
        }

        // Unique local fc00::/7 — first 7 bits are 1111 110
        if ((bytes[0] & 0xfe) == 0xfc)
        {
            return true;
        }

        // Multicast ff00::/8
        if (bytes[0] == 0xff)
        {
            return true;
        }

        return false;
    }

    private static uint IpToUint(string ipStr)
    {
        var bytes = IPAddress.Parse(ipStr).GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }

    private static uint PrefixLengthToMask(int prefixLength)
    {
        return prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);
    }
}
