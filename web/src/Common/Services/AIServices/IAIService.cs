namespace VulWall.Dashboard.Common.Services.AIServices;

public interface IAIService
{
    Task<string?> GetResponseAsync(string promptName, string userMessage, string? model = null, CancellationToken cancellationToken = default);
} 