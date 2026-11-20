using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using VulWall.Dashboard.Common.Services.Organization;

namespace VulWall.Dashboard.Extensions.Configuration;

/// <summary>
/// Chains custom OpenID Connect events onto Auth0 SDK's events.
/// Registered as IPostConfigureOptions to guarantee it runs AFTER Auth0's own IPostConfigureOptions,
/// which overwrites any events set via options.OpenIdConnectEvents or services.PostConfigure.
/// </summary>
public class Auth0EventConfiguration : IPostConfigureOptions<OpenIdConnectOptions>
{
    public void PostConfigure(string? name, OpenIdConnectOptions options)
    {
        if (name != OpenIdConnectDefaults.AuthenticationScheme)
            return;

        ChainOnTokenValidated(options);
        ChainOnRemoteFailure(options);
    }

    private static void ChainOnTokenValidated(OpenIdConnectOptions options)
    {
        var previous = options.Events.OnTokenValidated;

        options.Events.OnTokenValidated = async context =>
        {
            if (previous != null)
                await previous(context);

            var organizationSyncService = context.HttpContext.RequestServices
                .GetRequiredService<IOrganizationSyncService>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Auth0EventConfiguration>>();

            var auth0UserId = context.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var email = context.Principal?.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;

            if (!string.IsNullOrEmpty(auth0UserId))
            {
                try
                {
                    await organizationSyncService.SyncOrganizationOnLoginAsync(auth0UserId, email);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to sync organization on login for Auth0 User ID: {Auth0UserId}",
                        auth0UserId);
                }
            }
        };
    }

    /// <summary>
    /// Handles OIDC remote failures that the Auth0 SDK does not redirect gracefully.
    /// Known failures are handled before calling the Auth0 SDK's handler to prevent the SDK
    /// from partially writing response headers (which would block our redirect).
    /// Unknown failures fall through to the SDK's handler, then to /Error as a final fallback.
    /// </summary>
    private static void ChainOnRemoteFailure(OpenIdConnectOptions options)
    {
        var previous = options.Events.OnRemoteFailure;

        options.Events.OnRemoteFailure = async context =>
        {
            var message = context.Failure?.Message ?? string.Empty;
            var (error, errorDescription) = await ExtractRemoteErrorAsync(context.HttpContext.Request);

            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Auth0EventConfiguration>>();

            if (error.Equals("access_denied", StringComparison.OrdinalIgnoreCase)
                || message.Contains("access_denied", StringComparison.OrdinalIgnoreCase))
            {
                logger.LogInformation("Auth0 access_denied (email not verified) — redirecting to AccessDenied");
                context.Response.Redirect("/Error/AccessDenied");
                context.HandleResponse();
                return;
            }

            if (message.Contains("Correlation failed", StringComparison.OrdinalIgnoreCase)
                || message.Contains("correlation cookie", StringComparison.OrdinalIgnoreCase))
            {
                // Correlation cookie missing or state mismatch. Common cause: Auth0 "resume" flow
                // posts back with a cached prior state that doesn't match the new correlation cookie.
                logger.LogWarning("OIDC correlation failure — redirecting to login for fresh OIDC flow");
                context.Response.Redirect("/Account/Login");
                context.HandleResponse();
                return;
            }

            if ((error.Equals("invalid_request", StringComparison.OrdinalIgnoreCase)
                 && errorDescription.Contains("signup is disabled", StringComparison.OrdinalIgnoreCase))
                || errorDescription.Contains("signup is disabled", StringComparison.OrdinalIgnoreCase)
                || (message.Contains("invalid_request", StringComparison.OrdinalIgnoreCase)
                    && message.Contains("signup", StringComparison.OrdinalIgnoreCase)))
            {
                logger.LogWarning(
                    "Auth0 signup disabled (invalid_request). Error={Error}, Description={ErrorDescription}",
                    error,
                    errorDescription);
                context.Response.Redirect("/Error/SignupDisabled");
                context.HandleResponse();
                return;
            }

            if (previous != null)
                await previous(context);

            if (context.Result == null)
            {
                logger.LogError(context.Failure, "Unhandled OIDC remote failure: {Message}", message);
                context.Response.Redirect("/Error");
                context.HandleResponse();
            }
        };
    }

    private static async Task<(string Error, string ErrorDescription)> ExtractRemoteErrorAsync(HttpRequest request)
    {
        var error = request.Query["error"].ToString();
        var errorDescription = request.Query["error_description"].ToString();

        if (!request.HasFormContentType)
            return (error, errorDescription);

        var form = await request.ReadFormAsync();

        if (string.IsNullOrEmpty(error))
            error = form["error"].ToString();

        if (string.IsNullOrEmpty(errorDescription))
            errorDescription = form["error_description"].ToString();

        return (error, errorDescription);
    }
}
