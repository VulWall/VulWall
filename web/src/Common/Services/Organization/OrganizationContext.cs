using VulWall.Dashboard.Data.Repositories;
using OrgEntity = VulWall.Dashboard.Data.Entities.Organization.Organization;

namespace VulWall.Dashboard.Common.Services.Organization;

/// <summary>
/// Resolves the organization for the signed-in user. A self-hosted install has a single
/// organization, so every authenticated user maps to it. A hosted multi-tenant fork would
/// resolve the org from the user's claims here instead.
/// </summary>
public class OrganizationContext(
    IHttpContextAccessor httpContextAccessor,
    OrganizationRepository organizationRepository)
    : IOrganizationContext
{
    // Per-request cache (OrganizationContext is Scoped — one instance per request)
    private OrgEntity? _cachedOrg;

    public async Task<string> GetCurrentOrgIdAsync()
    {
        var org = await GetCurrentOrganizationAsync();
        return org.Id;
    }

    public async Task<OrgEntity> GetCurrentOrganizationAsync()
    {
        if (_cachedOrg != null)
            return _cachedOrg;

        if (httpContextAccessor.HttpContext?.User?.Identity?.IsAuthenticated != true)
            throw new UnauthorizedAccessException("User is not authenticated");

        _cachedOrg = await DefaultOrganization.GetAsync(organizationRepository)
                     ?? throw new InvalidOperationException("The default organization does not exist; it is created at startup.");
        return _cachedOrg;
    }
}
