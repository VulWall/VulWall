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
            ["heartbleed"] = "Heartbleed \u2014 Server memory can be read by attackers",
            ["CCS"] = "CCS Injection \u2014 Encrypted connections can be intercepted",
            ["ROBOT"] = "ROBOT Attack \u2014 RSA encryption can be broken",
            ["POODLE_SSL"] = "POODLE \u2014 Encrypted data can be stolen via SSLv3",
            ["DROWN"] = "DROWN Attack \u2014 SSLv2 weakness breaks TLS encryption",
            ["FREAK"] = "FREAK Attack \u2014 Encryption can be downgraded to breakable strength",
            ["LOGJAM"] = "Logjam \u2014 Key exchange can be downgraded to breakable strength",
            ["ticketbleed"] = "Ticketbleed \u2014 Session keys can leak from F5 load balancers",
            ["CRIME"] = "CRIME Attack \u2014 Session cookies can be stolen via TLS compression",
            ["CRIME_TLS"] = "CRIME Attack \u2014 Session cookies can be stolen via TLS compression",
            ["BREACH"] = "BREACH Attack \u2014 Sensitive data can leak through HTTP compression",
            ["SWEET32"] = "SWEET32 \u2014 Weak 64-bit ciphers allow data recovery",
            ["RC4"] = "Weak RC4 Cipher \u2014 Broken encryption algorithm still enabled",
            ["secure_renego"] = "Insecure TLS Renegotiation \u2014 Connections vulnerable to hijacking",
            ["BEAST"] = "BEAST Attack \u2014 Older CBC cipher weakness",
            ["BEAST_CBC_TLS1"] = "BEAST Attack \u2014 Older CBC cipher weakness in TLS 1.0",
            ["LUCKY13"] = "Lucky Thirteen \u2014 Low-risk timing attack on CBC ciphers",
            ["fallback_SCSV"] = "Missing TLS Fallback Protection \u2014 Server allows protocol downgrade",
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
