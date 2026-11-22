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
