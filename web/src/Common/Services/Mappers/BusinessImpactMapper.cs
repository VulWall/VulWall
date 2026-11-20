namespace VulWall.Dashboard.Common.Services.Mappers;

/// <summary>
/// Maps finding types to business impact sentences focused on
/// security questionnaires and compliance relevance.
/// </summary>
public static class BusinessImpactMapper
{
    private static readonly Dictionary<string, string> ImpactMap =
        new(StringComparer.OrdinalIgnoreCase)
        {
            // HTTP Headers
            ["missing-hsts"] =
                "Frequently flagged in security questionnaires. Without HSTS, enterprise customers may view your site as vulnerable to man-in-the-middle attacks.",
            ["missing-csp"] =
                "A top question in enterprise security reviews. Missing CSP signals weak protection against cross-site scripting to potential customers.",
            ["missing-x-frame-options"] =
                "Often checked in vendor assessments. Without this header, your app could be embedded in malicious sites to trick your users.",
            ["missing-x-content-type-options"] =
                "Listed in common security questionnaires. Missing this header may allow browsers to misinterpret files, creating security risks.",
            ["weak-x-content-type-options"] =
                "Flagged in security audits. The X-Content-Type-Options header is present but not properly configured, reducing its effectiveness against MIME-sniffing attacks.",
            ["missing-referrer-policy"] =
                "Assessed in privacy-focused security reviews. Without this, sensitive URL data may leak to third parties.",
            ["missing-permissions-policy"] =
                "Increasingly checked in compliance assessments. Controls which browser features your site can use, reducing your attack surface.",
            ["weak-hsts"] =
                "Security reviewers check HSTS configuration details. A weak policy may not meet the minimum thresholds required by enterprise customers.",
            ["weak-csp"] =
                "Enterprise security teams scrutinize CSP strength. A weak policy provides limited protection and may fail vendor security assessments.",
            ["header-disclosure-server"] =
                "Flagged in penetration tests and questionnaires. Exposing your server software helps attackers target known vulnerabilities.",
            ["header-disclosure-x-powered-by"] =
                "Commonly noted in security audits. Revealing your technology stack gives attackers a head start in finding exploits.",
            ["header-disclosure-x-aspnet-version"] =
                "Flagged in penetration tests. Exposing the ASP.NET version helps attackers target known framework vulnerabilities.",
            ["header-disclosure-x-aspnetmvc-version"] =
                "Noted in security audits. Revealing the ASP.NET MVC version narrows the attack surface for targeted exploits.",
            ["header-disclosure-x-generator"] =
                "Checked in vendor assessments. Disclosing your site generator (e.g., WordPress version) helps attackers find known vulnerabilities.",
            ["header-disclosure-x-runtime"] =
                "May be flagged in security reviews. Reveals server-side processing time and confirms the technology stack in use, aiding targeted reconnaissance.",
            ["header-disclosure-x-varnish"] =
                "Noted in security audits. Revealing cache proxy details exposes infrastructure information to potential attackers.",
            ["header-disclosure-x-page-speed"] =
                "May be noted in security reviews. Disclosing the use of PageSpeed modules reveals server-side optimization details.",
            ["header-disclosure-x-drupal-cache"] =
                "Flagged in penetration tests. Exposing Drupal cache headers confirms the CMS in use, aiding targeted attacks.",

            // Email Security
            ["missing-spf"] =
                "Checked in nearly every enterprise security questionnaire. Without SPF, anyone can send emails pretending to be your company, undermining customer trust.",
            ["spf-allows-all"] =
                "A critical misconfiguration that enterprise reviewers flag immediately. Your SPF record currently authorizes any server in the world to send email as your domain.",
            ["spf-softfail-all"] =
                "May be noted in security assessments as an incomplete configuration. Soft-fail provides weaker protection than a strict SPF policy and signals unfinished email hardening.",
            ["missing-dmarc"] =
                "A top question in vendor security reviews and SOC 2 readiness checks. Without DMARC, you have no policy to prevent spoofed emails from reaching your customers.",
            ["dmarc-policy-none"] =
                "Frequently scrutinized in compliance assessments. A DMARC policy of 'none' means spoofed emails are still delivered, which enterprise buyers see as unenforced email security.",
            ["dmarc-no-rua"] =
                "May be flagged in mature security reviews. Without DMARC aggregate reporting, you cannot monitor who is sending email on your behalf or detect spoofing attempts.",
            ["missing-dkim"] =
                "Occasionally checked in security questionnaires. DKIM adds a cryptographic signature to your emails, helping recipients verify they were not tampered with in transit.",
            ["dns-zone-transfer"] =
                "A critical finding in any penetration test or security review. Open zone transfers expose your complete DNS infrastructure, giving attackers a full map of internal hostnames, staging servers, and services.",

            // CORS
            ["cors-wildcard-origin"] =
                "Flagged in penetration tests and vendor assessments. A wildcard CORS policy allows any website to read data from your application, which may expose sensitive information to unauthorized parties.",
            ["cors-origin-reflected"] =
                "A serious finding in any security review. Reflecting arbitrary origins in CORS headers allows attackers to steal data from your users' authenticated sessions via malicious websites.",
            ["cors-credentials-with-wildcard"] =
                "A CORS misconfiguration flagged in penetration tests. Setting credentials with a wildcard origin indicates a fundamental configuration error that should be corrected, even though modern browsers block this combination.",

            // HTTPS
            ["missing-https-redirect"] =
                "A baseline expectation in every security questionnaire. Without HTTP-to-HTTPS redirection, user traffic can be intercepted, which immediately fails vendor security assessments.",

            // Security Policy
            ["missing-security-txt"] =
                "Increasingly checked in vendor security assessments. A security.txt file signals that you have a vulnerability disclosure policy, which security-conscious customers expect.",
        };

    /// <summary>
    /// Returns a business impact sentence for a finding type, or null if unmapped.
    /// </summary>
    public static string? GetBusinessImpact(string? findingType)
    {
        if (findingType != null && ImpactMap.TryGetValue(findingType, out var impact))
            return impact;

        return null;
    }
}
