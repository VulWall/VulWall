using OrgEntity = VulWall.Dashboard.Data.Entities.Organization.Organization;

namespace VulWall.Dashboard.Common.Services.Organization;

public interface IOrganizationContext
{
    /// <summary>
    /// Gets the organization ID for the currently authenticated user.
    /// Throws UnauthorizedAccessException if user is not authenticated.
    /// </summary>
    Task<string> GetCurrentOrgIdAsync();

    /// <summary>
    /// Gets the full Organization entity for the current user.
    /// </summary>
    Task<OrgEntity> GetCurrentOrganizationAsync();
}
