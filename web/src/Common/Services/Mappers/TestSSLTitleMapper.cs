namespace VulWall.Dashboard.Common.Services.Mappers;

/// <summary>
/// Maps cryptic TestSSL finding IDs (e.g., "BREACH", "heartbleed") to
/// human-readable titles for non-technical SaaS founders.
/// </summary>
public static class TestSSLTitleMapper
{
    private static readonly Dictionary<string, string> TitleMap =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["heartbleed"] = "Heartbleed: Server memory can be read by attackers",
            ["CCS"] = "CCS Injection: Encrypted connections can be intercepted",
            ["ROBOT"] = "ROBOT Attack: RSA encryption can be broken",
            ["POODLE_SSL"] = "POODLE: Encrypted data can be stolen via SSLv3",
            ["DROWN"] = "DROWN Attack: SSLv2 weakness breaks TLS encryption",
            ["FREAK"] = "FREAK Attack: Encryption can be downgraded to breakable strength",
            ["LOGJAM"] = "Logjam: Key exchange can be downgraded to breakable strength",
            ["ticketbleed"] = "Ticketbleed: Session keys can leak from F5 load balancers",
            ["CRIME"] = "CRIME Attack: Session cookies can be stolen via TLS compression",
            ["CRIME_TLS"] = "CRIME Attack: Session cookies can be stolen via TLS compression",
            ["BREACH"] = "BREACH Attack: Sensitive data can leak through HTTP compression",
            ["SWEET32"] = "SWEET32: Weak 64-bit ciphers allow data recovery",
            ["RC4"] = "Weak RC4 Cipher: Broken encryption algorithm still enabled",
            ["secure_renego"] = "Insecure TLS Renegotiation: Connections vulnerable to hijacking",
            ["BEAST"] = "BEAST Attack: Older CBC cipher weakness",
            ["BEAST_CBC_TLS1"] = "BEAST Attack: Older CBC cipher weakness in TLS 1.0",
            ["LUCKY13"] = "Lucky Thirteen: Low-risk timing attack on CBC ciphers",
            ["fallback_SCSV"] = "Missing TLS Fallback Protection: Server allows protocol downgrade",
        };

    /// <summary>
    /// Returns a human-readable title for a testssl finding, or the original title if unmapped.
    /// </summary>
    public static string MapTitle(string? findingType, string originalTitle)
    {
        if (findingType != null && TitleMap.TryGetValue(findingType, out var mapped))
            return mapped;

        return originalTitle;
    }
}
