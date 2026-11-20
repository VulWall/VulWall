using VulWall.Dashboard.Common.Services.Auth0;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Common.Services.Organization;

public interface IOrganizationSyncService
{
    Task SyncOrganizationOnLoginAsync(string auth0UserId, string? email);
}

public class OrganizationSyncService(
    OrganizationRepository organizationRepository,
    IAuth0ManagementService auth0Service,
    ILogger<OrganizationSyncService> logger)
    : IOrganizationSyncService
{
    public async Task SyncOrganizationOnLoginAsync(string auth0UserId, string? email)
    {
        if (string.IsNullOrEmpty(auth0UserId))
        {
            logger.LogWarning("Auth0UserId is null or empty, skipping organization sync");
            return;
        }

        try
        {
            var userOrgs = (await organizationRepository.FindAsync(o => o.UserIds.Contains(auth0UserId))).ToList();

            if (userOrgs.Count == 0)
                return;

            // User already belongs to one or more orgs — sync metadata only.
            await SyncEmailAndAuth0MetadataAsync(auth0UserId, userOrgs, email);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to sync organization on login for user {UserId}", auth0UserId);
            throw;
        }
    }

    private async Task SyncEmailAndAuth0MetadataAsync(
        string auth0UserId,
        List<Data.Entities.Organization.Organization> userOrgs,
        string? email)
    {
        // Update owner email on the primary org if missing
        var primaryOrg = userOrgs[0];
        if (!string.IsNullOrEmpty(email) && string.IsNullOrEmpty(primaryOrg.OwnerEmail))
        {
            primaryOrg.OwnerEmail = email;
            primaryOrg.UpdatedAt = DateTime.UtcNow;
            await organizationRepository.UpdateAsync(primaryOrg);
            logger.LogInformation("Updated owner email for organization {OrgId}", primaryOrg.Id);
        }

        // For multi-org users, leave app_metadata.org_id as a hint only (set to primary org).
        // For single-org users, keep it in sync.
        try
        {
            var claimOrgId = await auth0Service.GetUserOrgIdAsync(auth0UserId);
            var primaryOrgId = primaryOrg.Id;

            var claimIsValid = !string.IsNullOrEmpty(claimOrgId)
                               && userOrgs.Any(o => o.Id == claimOrgId);

            if (!claimIsValid)
            {
                await auth0Service.UpdateUserOrgIdAsync(auth0UserId, primaryOrgId);
                logger.LogInformation("Updated Auth0 org_id hint to {OrgId} for user {UserId}", primaryOrgId, auth0UserId);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed to sync Auth0 org_id hint for user {UserId}", auth0UserId);
        }
    }
}
