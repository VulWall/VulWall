using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.Filters;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Attributes;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public class AuditLogAttribute : ActionFilterAttribute
{
    public AuditLogCategory Category { get; set; }
    public string Action { get; set; } = string.Empty;
    public string? AdditionalInfo { get; set; }

    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var executedContext = await next();

        if (executedContext.Exception == null && ShouldLogAudit(executedContext))
        {
            await LogAuditAsync(executedContext);
        }
    }

    private bool ShouldLogAudit(ActionExecutedContext context)
    {
        var statusCode = context.HttpContext.Response.StatusCode;

        if (statusCode is < 200 or >= 300)
        {
            return false;
        }

        var httpMethod = context.HttpContext.Request.Method;
        if (httpMethod is "POST" or "PUT" or "PATCH" or "DELETE")
        {
            if (context.ModelState is { IsValid: false })
            {
                return false;
            }
        }

        return true;
    }

    private async Task LogAuditAsync(ActionExecutedContext context)
    {
        try
        {
            var repository = context.HttpContext.RequestServices.GetService<AuditLogRepository>();
            if (repository == null)
            {
                return;
            }

            var httpContext = context.HttpContext;
            var user = httpContext.User;

            var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                        ?? user.FindFirst("sub")?.Value
                        ?? "Unknown";

            var userName = user.FindFirst(ClaimTypes.Name)?.Value
                          ?? user.FindFirst("name")?.Value
                          ?? user.FindFirst(ClaimTypes.Email)?.Value
                          ?? user.FindFirst("email")?.Value
                          ?? "Unknown User";

            var auditLog = new AuditLog
            {
                UserId = userId,
                UserName = userName,
                Category = Category,
                Action = Action,
                AdditionalInfo = AdditionalInfo ?? GetAdditionalInfoFromRoute(context),
                IpAddress = httpContext.Connection.RemoteIpAddress?.ToString(),
                CreatedAt = DateTime.UtcNow
            };

            await repository.CreateAsync(auditLog);
        }
        catch (Exception ex)
        {
            var logger = context.HttpContext.RequestServices.GetService<ILogger<AuditLogAttribute>>();
            logger?.LogError(ex, "Failed to create audit log entry");
        }
    }

    private string? GetAdditionalInfoFromRoute(ActionExecutedContext context)
    {
        if (context.RouteData.Values.TryGetValue("domain", out var domain))
        {
            return $"for {domain}";
        }

        return null;
    }
}
