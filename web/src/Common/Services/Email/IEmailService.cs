namespace VulWall.Dashboard.Common.Services.Email;

public interface IEmailService
{
    Task<bool> SendTemplateAsync(string to, EmailTemplate template, Dictionary<string, object> variables, string? subject = null);
}
