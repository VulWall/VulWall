namespace VulWall.Dashboard.Assets.Validation;

/// <summary>
/// Decides whether a signed-in user is implicitly the owner of a domain asset,
/// based on their email domain. Used to auto-verify corporate signups
/// (e.g. alice@acme.com adding acme.com) while everyone else falls back
/// to the DNS-TXT verification flow.
/// </summary>
public static class EmailDomainMatcher
{
    // ponytail: hand-maintained list, ~20 providers covers the abuse vector; extend if a new freemail domain shows up.
    private static readonly HashSet<string> FreemailDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "ymail.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "proton.me",
        "protonmail.com",
        "gmx.com",
        "gmx.net",
        "aol.com",
        "zoho.com",
        "yandex.com",
        "yandex.ru",
        "hey.com",
        "mail.com",
        "qq.com",
        "163.com",
        "126.com",
        "web.de",
        "gmx.de",
        "pm.me",
        "fastmail.com",
        "tuta.com",
        "tutanota.com",
        "hotmail.co.uk",
        "yahoo.co.uk",
        "yahoo.fr",
        "live.co.uk",
        // Disposable / throwaway providers.
        "mailinator.com",
        "guerrillamail.com",
        "10minutemail.com",
        "yopmail.com",
        "temp-mail.org",
        "hetzez.com",
    };

    /// <summary>
    /// Extracts the normalized (trimmed, lowercased) domain from an email address, but only
    /// when that domain is one a user could plausibly own — i.e. not a freemail/disposable
    /// provider. Returns null for null/whitespace input, a missing '@', an empty local part
    /// ("@x"), a trailing '@' ("x@"), an empty domain, or any freemail domain (fail closed).
    /// This is the single source of truth for "which domain, if any, does this email entitle
    /// the user to auto-verify".
    /// </summary>
    public static string? GetOwnableDomain(string? userEmail)
    {
        if (string.IsNullOrWhiteSpace(userEmail))
        {
            return null;
        }

        // Reject no-'@', empty local part ("@x") and trailing-'@' ("x@"): none is a real address.
        var atIndex = userEmail.LastIndexOf('@');
        if (atIndex <= 0 || atIndex == userEmail.Length - 1)
        {
            return null;
        }

        var emailDomain = userEmail[(atIndex + 1)..].Trim().ToLowerInvariant();
        if (emailDomain.Length == 0 || FreemailDomains.Contains(emailDomain))
        {
            return null;
        }

        return emailDomain;
    }

    /// <summary>
    /// Returns true when the user's email domain proves ownership of the asset domain:
    /// the asset domain equals the email domain, or is a subdomain of it. Freemail
    /// senders never imply ownership. Null/malformed input returns false (fail closed).
    /// </summary>
    public static bool IsOwnershipImpliedByEmail(string? userEmail, string assetDomain)
    {
        if (string.IsNullOrWhiteSpace(assetDomain))
        {
            return false;
        }

        var emailDomain = GetOwnableDomain(userEmail);
        if (emailDomain == null)
        {
            return false;
        }

        var asset = assetDomain.Trim().ToLowerInvariant();

        // ponytail: exact-suffix match, no Public Suffix List. Corp domain on a different TLD (email @acme.io vs asset acme.com) simply falls back to DNS-TXT — safe, just not auto. Add PSL/eTLD+1 only if that friction bites.
        return asset == emailDomain || asset.EndsWith("." + emailDomain, StringComparison.Ordinal);
    }
}
