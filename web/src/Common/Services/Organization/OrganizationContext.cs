using System.Security.Claims;
using VulWall.Dashboard.Data.Repositories;
using OrgEntity = VulWall.Dashboard.Data.Entities.Organization.Organization;

namespace VulWall.Dashboard.Common.Services.Organization;

public class OrganizationContext(
    IHttpContextAccessor httpContextAccessor,
    OrganizationRepository organizationRepository,
    ILogger<OrganizationContext> logger)
    : IOrganizationContext
{
    private const string SessionKey = "active_org_id";
    private const string OrgIdClaimType = "https://vulwall.com/org_id";

    // Per-request cache (OrganizationContext is Scoped — one instance per request)
    private List<OrgEntity>? _cachedUserOrgs;
    private OrgEntity? _cachedActiveOrg;

    public async Task<string> GetCurrentOrgIdAsync()
    {
        var org = await GetCurrentOrganizationAsync();
        return org.Id;
    }

    public async Task<OrgEntity> GetCurrentOrganizationAsync()
    {
        if (_cachedActiveOrg != null)
            return _cachedActiveOrg;

        var httpContext = RequireAuthenticatedContext();
        var auth0UserId = RequireUserId(httpContext);

        var userOrgs = await GetOrLoadUserOrgsAsync(auth0UserId);

        if (userOrgs.Count == 0)
        {
            // User with zero orgs reaching the dashboard is a bug — OrganizationSyncService
            // should have created one during login. Don't silently create an incomplete org.
            logger.LogError("User {UserId} has no organizations — sync service may have failed", auth0UserId);
            throw new InvalidOperationException(
                $"User {auth0UserId} does not belong to any organization. " +
                "This should have been handled by OrganizationSyncService during login.");
        }

        var sessionOrgId = httpContext.Session.GetString(SessionKey);
        if (!string.IsNullOrEmpty(sessionOrgId))
        {
            var sessionOrg = userOrgs.FirstOrDefault(o => o.Id == sessionOrgId);
            if (sessionOrg != null)
            {
                logger.LogDebug("Resolved active org {OrgId} from session for user {UserId}", sessionOrgId, auth0UserId);
                _cachedActiveOrg = sessionOrg;
                return sessionOrg;
            }

            logger.LogWarning("Session org_id {OrgId} is not in user's org list, clearing", sessionOrgId);
            httpContext.Session.Remove(SessionKey);
        }

        var claimOrgId = httpContext.User.FindFirst(OrgIdClaimType)?.Value;
        var activeOrg = (!string.IsNullOrEmpty(claimOrgId)
                             ? userOrgs.FirstOrDefault(o => o.Id == claimOrgId)
                             : null)
                        ?? userOrgs[0];

        WriteActiveOrgToSession(httpContext, activeOrg.Id);
        logger.LogDebug("Set active org {OrgId} in session for user {UserId}", activeOrg.Id, auth0UserId);
        _cachedActiveOrg = activeOrg;
        return activeOrg;
    }

    public async Task<IReadOnlyList<OrgEntity>> GetUserOrganizationsAsync()
    {
        var httpContext = RequireAuthenticatedContext();
        var auth0UserId = RequireUserId(httpContext);
        var orgs = await GetOrLoadUserOrgsAsync(auth0UserId);
        return orgs.AsReadOnly();
    }

    private async Task<List<OrgEntity>> GetOrLoadUserOrgsAsync(string auth0UserId)
    {
        if (_cachedUserOrgs != null)
            return _cachedUserOrgs;

        // Reuse orgs already fetched by EnsureOrganizationMiddleware
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext?.Items[OrganizationContextKeys.UserOrgs] is List<OrgEntity> middlewareOrgs)
        {
            _cachedUserOrgs = middlewareOrgs;
            return _cachedUserOrgs;
        }

        _cachedUserOrgs = (await organizationRepository.FindAsync(o => o.UserIds.Contains(auth0UserId))).ToList();
        return _cachedUserOrgs;
    }

    private HttpContext RequireAuthenticatedContext()
    {
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext?.User?.Identity?.IsAuthenticated != true)
            throw new UnauthorizedAccessException("User is not authenticated");
        return httpContext;
    }

    private static string RequireUserId(HttpContext httpContext)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
            throw new UnauthorizedAccessException("User ID not found in claims");
        return userId;
    }

    private static void WriteActiveOrgToSession(HttpContext httpContext, string orgId)
    {
        httpContext.Session.SetString(SessionKey, orgId);
    }

}
