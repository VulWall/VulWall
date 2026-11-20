using OrgEntity = VulWall.Dashboard.Data.Entities.Organization.Organization;

namespace VulWall.Dashboard.Common.Services.Organization;

public interface IOrganizationContext
{
    /// <summary>
    /// Gets the organization ID for the currently authenticated user.
    /// Resolves from session first, falls back to DB. Creates an org if the user has none.
    /// Throws UnauthorizedAccessException if user is not authenticated.
    /// </summary>
    Task<string> GetCurrentOrgIdAsync();

    /// <summary>
    /// Gets the full Organization entity for the current user's active org.
    /// </summary>
    Task<OrgEntity> GetCurrentOrganizationAsync();

    /// <summary>
    /// Returns all organizations the current user belongs to.
    /// </summary>
    Task<IReadOnlyList<OrgEntity>> GetUserOrganizationsAsync();
}
