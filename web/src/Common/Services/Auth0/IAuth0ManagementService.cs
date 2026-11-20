namespace VulWall.Dashboard.Common.Services.Auth0;

public interface IAuth0ManagementService
{
    /// <summary>
    /// Updates the user's app_metadata with the organization ID
    /// </summary>
    Task UpdateUserOrgIdAsync(string auth0UserId, string orgId);

    /// <summary>
    /// Gets the org_id from user's app_metadata if it exists
    /// </summary>
    Task<string?> GetUserOrgIdAsync(string auth0UserId);

    /// <summary>
    /// Permanently deletes the Auth0 user. Requires the delete:users scope on the
    /// Management API machine-to-machine application.
    /// </summary>
    Task DeleteUserAsync(string auth0UserId);
}
