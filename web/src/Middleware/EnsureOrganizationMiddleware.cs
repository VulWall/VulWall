using System.Security.Claims;
using VulWall.Dashboard.Common.Services.Auth0;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings.Models;

namespace VulWall.Dashboard.Middleware;

public class EnsureOrganizationMiddleware(RequestDelegate next)
{
    private const string PendingClaimTokenKey = "pending_claim_token";

    public async Task InvokeAsync(
        HttpContext context,
        OrganizationRepository organizationRepository,
        IAuth0ManagementService auth0Service,
        ILogger<EnsureOrganizationMiddleware> logger)
    {
        if (context.User.Identity?.IsAuthenticated == true
            && !IsClaimPath(context.Request.Path))
        {
            var auth0UserId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(auth0UserId))
            {
                var userOrgs = (await organizationRepository.FindAsync(o => o.UserIds.Contains(auth0UserId))).ToList();
                context.Items[OrganizationContextKeys.UserOrgs] = userOrgs;
                if (userOrgs.Count == 0)
                {
                    // If a claim is in-flight (token stored before Auth0 redirect), send the user
                    // to complete it rather than creating a blank org they'll have to abandon.
                    context.Request.Cookies.TryGetValue(PendingClaimTokenKey, out var pendingToken);
                    if (!string.IsNullOrEmpty(pendingToken))
                    {
                        context.Response.Cookies.Delete(PendingClaimTokenKey, new CookieOptions
                        {
                            Path = "/",
                            Secure = true,
                            SameSite = SameSiteMode.Lax
                        });
                        context.Response.Redirect($"/claim/complete?token={Uri.EscapeDataString(pendingToken)}");
                        return;
                    }

                    await CreateOrganizationForUserAsync(auth0UserId, context.User, organizationRepository, auth0Service, logger);
                }
            }
        }

        await next(context);
    }

    private static bool IsClaimPath(PathString path)
    {
        return path.StartsWithSegments("/claim", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task CreateOrganizationForUserAsync(
        string auth0UserId,
        ClaimsPrincipal user,
        OrganizationRepository organizationRepository,
        IAuth0ManagementService auth0Service,
        ILogger<EnsureOrganizationMiddleware> logger)
    {
        var email = user.FindFirst(ClaimTypes.Email)?.Value;

        var newOrg = new Data.Entities.Organization.Organization
        {
            UserIds = new List<string> { auth0UserId },
            OwnerEmail = email,
            IsClaimed = true,
            CertVisible = true,
            SubscriptionSettings = Plans.GetDefaultSubscriptionSettings(),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await organizationRepository.CreateAsync(newOrg);
        logger.LogInformation("Created organization {OrgId} for user {UserId}", newOrg.Id, auth0UserId);

        try
        {
            await auth0Service.UpdateUserOrgIdAsync(auth0UserId, newOrg.Id);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to sync new org {OrgId} to Auth0 for user {UserId}", newOrg.Id, auth0UserId);
        }
    }
}
