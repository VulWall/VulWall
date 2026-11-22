using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace VulWall.Dashboard.Assets.Services;

/// <summary>
/// The scanner's discovery ids (<c>scanner/src/internal/shared/ids.go</c>): a UUIDv5 (SHA-1) of
/// "org:&lt;org&gt;:&lt;type&gt;:&lt;value&gt;" in the scanner's namespace, so a host or IP has one
/// discovery per org whoever finds it. Keep the two in step: DiscoveryIdsTests and the scanner's
/// TestDiscoveryIDGoldenVectors hold the same vectors.
/// </summary>
internal static class DiscoveryIds
{
    private static readonly Guid Namespace = Guid.Parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8");

    /// <summary>
    /// The discovery a domain asset's scan writes for its own host. The scanner decides by the
    /// dot count of the host (<c>determineDomainAssetType</c>, a job without a parent): more than
    /// one dot is a subdomain, so <c>api.a.com</c> gets the id it has when found under
    /// <c>a.com</c>, and so does a two-label root like <c>example.co.uk</c>.
    /// </summary>
    public static string ForDomainAsset(string orgId, string host) =>
        host.Count(c => c == '.') > 1 ? Subdomain(orgId, host) : Domain(orgId, host);

    public static string Domain(string orgId, string domain) =>
        V5($"org:{orgId}:domain:{domain.Trim().ToLowerInvariant()}");

    public static string Subdomain(string orgId, string subdomain) =>
        V5($"org:{orgId}:subdomain:{subdomain.Trim().ToLowerInvariant()}");

    /// <summary>Trimmed only, not lower-cased, as in the scanner.</summary>
    public static string Ip(string orgId, string ip) =>
        V5($"org:{orgId}:ip:{ip.Trim()}");

    /// <summary>
    /// <paramref name="ip"/> as Go's <c>net.IP.String()</c> writes it, which is how the scanner
    /// stores the addresses DNS finds: IPv4 dotted, an IPv4-mapped IPv6 address as plain IPv4,
    /// other IPv6 in lower case with the longest run of two or more zero groups compressed (the
    /// first one on a tie), and no embedded IPv4 or zone. The IP id is not normalised, so an IP
    /// asset must be stored in this form to meet the discovery its DNS-found twin has.
    /// </summary>
    public static string CanonicalIp(string ip)
    {
        var address = IPAddress.Parse(ip.Trim());
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork)
            return address.ToString();

        var bytes = address.GetAddressBytes();
        var groups = new int[8];
        for (var i = 0; i < 8; i++)
            groups[i] = (bytes[2 * i] << 8) | bytes[2 * i + 1];

        int bestStart = -1, bestLength = 1;
        for (var i = 0; i < 8; i++)
        {
            var j = i;
            while (j < 8 && groups[j] == 0) j++;
            if (j - i > bestLength)
                (bestStart, bestLength) = (i, j - i);
            i = Math.Max(i, j);
        }

        var parts = new List<string>();
        for (var i = 0; i < 8; i++)
        {
            if (i == bestStart)
            {
                parts.Add(i == 0 ? ":" : "");
                i += bestLength - 1;
                if (i == 7) parts.Add("");
                continue;
            }
            parts.Add(groups[i].ToString("x"));
        }
        return string.Join(":", parts);
    }

    // RFC 4122 version 5, as Go's uuid.NewSHA1: SHA-1 of the namespace bytes (big-endian) and
    // the name, first 16 bytes, version 5 and the RFC variant.
    private static string V5(string name)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var input = new byte[16 + nameBytes.Length];
        Namespace.TryWriteBytes(input, bigEndian: true, out _);
        nameBytes.CopyTo(input, 16);

        var hash = SHA1.HashData(input);
        hash[6] = (byte)((hash[6] & 0x0F) | 0x50);
        hash[8] = (byte)((hash[8] & 0x3F) | 0x80);
        return new Guid(hash.AsSpan(0, 16), bigEndian: true).ToString();
    }
}
