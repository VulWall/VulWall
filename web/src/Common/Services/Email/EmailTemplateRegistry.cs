using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Common.Services.Email;

/// <summary>
/// Central registry mapping each EmailTemplate enum value to its Resend template ID and subject.
/// Template IDs are read from environment variables via ServiceSettings.
/// Returns null for any template whose ID is not configured, so callers don't need to guard individually.
/// </summary>
public class EmailTemplateRegistry
{
    private readonly Dictionary<EmailTemplate, (string TemplateId, string Subject)> _templates;

    public EmailTemplateRegistry()
    {
        var settings = ServiceSettings.Instance;

        _templates = new Dictionary<EmailTemplate, (string, string)>();

        if (!string.IsNullOrWhiteSpace(settings.ResendScanCompleteTemplate))
            _templates[EmailTemplate.ScanComplete] = (settings.ResendScanCompleteTemplate, "Scan Result");

        if (!string.IsNullOrWhiteSpace(settings.ResendDeleteAccountTemplateId))
            _templates[EmailTemplate.DeleteAccountVerification] = (settings.ResendDeleteAccountTemplateId, "Your VulWall account deletion verification code");

    }

    /// <summary>
    /// Returns the template ID and subject for the given template, or null if the template is not configured.
    /// </summary>
    public (string TemplateId, string Subject)? GetTemplate(EmailTemplate template)
    {
        return _templates.TryGetValue(template, out var entry) ? entry : null;
    }
}
