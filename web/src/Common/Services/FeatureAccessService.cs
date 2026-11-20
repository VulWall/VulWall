using VulWall.Dashboard.Common.Models;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Common.Services;

/// <summary>
/// Service to determine feature access based on subscription tier.
/// Use this service to check what features a user can access.
/// </summary>
public class FeatureAccessService(
    IOrganizationContext orgContext,
    OrganizationRepository organizationRepository,
    ILogger<FeatureAccessService> logger)
{
    private const string ProPlanName = "Pro";
    private const string FreePlanName = "Free";

    /// <summary>
    /// Gets the feature access for the current organization.
    /// </summary>
    public async Task<FeatureAccess> GetFeatureAccessAsync()
    {
        try
        {
            var orgId = await orgContext.GetCurrentOrgIdAsync();
            var organization = await organizationRepository.GetByIdAsync(orgId);

            if (organization == null)
            {
                logger.LogWarning("Organization {OrgId} not found, defaulting to Free tier", orgId);
                return FeatureAccess.Free;
            }

            var isPro = organization.Plan?.IsActive == true &&
                        string.Equals(organization.Plan.SubscriptionPlan, ProPlanName, StringComparison.OrdinalIgnoreCase);

            var planName = isPro ? ProPlanName : FreePlanName;

            logger.LogDebug("Feature access for org {OrgId}: Plan={PlanName}, IsPro={IsPro}",
                orgId, planName, isPro);

            return new FeatureAccess
            {
                IsPro = isPro
            };
        }
        catch (UnauthorizedAccessException)
        {
            logger.LogDebug("User not authenticated, defaulting to Free tier");
            return FeatureAccess.Free;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error determining feature access, defaulting to Free tier");
            return FeatureAccess.Free;
        }
    }

    /// <summary>
    /// Quick check if the current organization has Pro access.
    /// </summary>
    public async Task<bool> HasProAccessAsync()
    {
        var access = await GetFeatureAccessAsync();
        return access.IsPro;
    }
}
