namespace VulWall.Dashboard.Common.Services.Email;

/// <summary>
/// Default <see cref="IEmailService"/> for self-hosted installs: no mail transport is configured,
/// so sends are logged and reported as not delivered. Register a real implementation
/// (for example SMTP) in place of this one to enable email.
/// </summary>
public sealed class NullEmailService(ILogger<NullEmailService> logger) : IEmailService
{
    public Task<bool> SendTemplateAsync(string to, EmailTemplate template, Dictionary<string, object> variables, string? subject = null)
    {
        logger.LogDebug("Email transport not configured; skipping {Template} email", template);
        return Task.FromResult(false);
    }
}
