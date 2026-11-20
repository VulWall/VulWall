using System.Security.Claims;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Middleware;

/// <summary>
/// Middleware to log successful login events after authentication
/// </summary>
public class LoginAuditMiddleware(RequestDelegate next)
{
    private const string LoginLoggedKey = "LoginLogged";

    public async Task InvokeAsync(HttpContext context, AuditLogRepository auditLogRepository)
    {
        // Only process authenticated requests
        if (context.User.Identity?.IsAuthenticated == true)
        {
            // Check if we've already logged this login session
            if (!context.Session.Keys.Contains(LoginLoggedKey))
            {
                // Mark this session as logged to avoid duplicate entries
                context.Session.SetString(LoginLoggedKey, "true");

                // Log the login event
                await LogLoginAsync(context, auditLogRepository);
            }
        }

        await next(context);
    }

    private async Task LogLoginAsync(HttpContext context, AuditLogRepository auditLogRepository)
    {
        try
        {
            var user = context.User;

            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                        ?? user.FindFirst("sub")?.Value
                        ?? "Unknown";

            var userName = user.FindFirst(ClaimTypes.Name)?.Value
                          ?? user.FindFirst("name")?.Value
                          ?? user.FindFirst(ClaimTypes.Email)?.Value
                          ?? user.FindFirst("email")?.Value
                          ?? "Unknown User";

            var isAdmin = string.Equals(
                user.FindFirst("https://vulwall.com/is_admin")?.Value,
                "true",
                StringComparison.OrdinalIgnoreCase);

            var auditLog = new AuditLog
            {
                UserId = userId,
                UserName = userName,
                Category = AuditLogCategory.Account,
                Action = "Logged in",
                IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                IsAdminAction = isAdmin,
                CreatedAt = DateTime.UtcNow
            };

            await auditLogRepository.CreateAsync(auditLog);
        }
        catch (Exception ex)
        {
            // Don't fail the request if audit logging fails
            var logger = context.RequestServices.GetService<ILogger<LoginAuditMiddleware>>();
            logger?.LogError(ex, "Failed to create login audit log entry");
        }
    }
}
