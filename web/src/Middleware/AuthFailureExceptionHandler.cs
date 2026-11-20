using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics;

namespace VulWall.Dashboard.Middleware;

/// <summary>
/// Fallback handler for authentication failures that escape the remote-failure hook.
/// Primary handling is in Auth0EventConfiguration.ChainOnRemoteFailure; this catches anything
/// that propagates as an unhandled AuthenticationFailureException instead.
/// </summary>
public class AuthFailureExceptionHandler : IExceptionHandler
{
    public ValueTask<bool> TryHandleAsync(
        HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        if (exception is not AuthenticationFailureException)
            return ValueTask.FromResult(false);

        var message = exception.Message;
        var innerMessage = exception.InnerException?.Message ?? string.Empty;

        if (message.Contains("access_denied", StringComparison.OrdinalIgnoreCase)
            || innerMessage.Contains("access_denied", StringComparison.OrdinalIgnoreCase))
        {
            httpContext.Response.Redirect("/Error/AccessDenied");
            return ValueTask.FromResult(true);
        }

        if ((message.Contains("invalid_request", StringComparison.OrdinalIgnoreCase)
             || innerMessage.Contains("invalid_request", StringComparison.OrdinalIgnoreCase))
            && (message.Contains("signup is disabled", StringComparison.OrdinalIgnoreCase)
                || innerMessage.Contains("signup is disabled", StringComparison.OrdinalIgnoreCase)))
        {
            httpContext.Response.Redirect("/Error/SignupDisabled");
            return ValueTask.FromResult(true);
        }

        return ValueTask.FromResult(false);
    }
}
