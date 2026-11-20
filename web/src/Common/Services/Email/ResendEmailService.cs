using Resend;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Common.Services.Email;

public class ResendEmailService(EmailTemplateRegistry registry, ILogger<ResendEmailService> logger) : IEmailService
{
    public async Task<bool> SendTemplateAsync(string to, EmailTemplate template, Dictionary<string, object> variables, string? subject = null)
    {
        var templateEntry = registry.GetTemplate(template);
        if (templateEntry is null)
        {
            logger.LogWarning("Email template {Template} is not configured. Skipping email send", template);
            return false;
        }

        var client = CreateClient();
        if (client is null) return false;

        try
        {
            var message = new EmailMessage
            {
                From = ServiceSettings.Instance.ResendFromEmail,
                To = [to],
                Subject = subject ?? templateEntry.Value.Subject,
                Template = new EmailMessageTemplate
                {
                    TemplateId = Guid.Parse(templateEntry.Value.TemplateId),
                    Variables = variables
                }
            };

            var response = await client.EmailSendAsync(message);
            logger.LogInformation("Email sent via template {Template} to {To}, Resend ID: {Id}", template, to, response.Content);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send template email {Template} to {To}", template, to);
            return false;
        }
    }

    private IResend? CreateClient()
    {
        var apiKey = ServiceSettings.Instance.ResendApiKey;
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            logger.LogWarning("Resend API key is not configured. Skipping email send");
            return null;
        }

        return ResendClient.Create(apiKey);
    }
}
