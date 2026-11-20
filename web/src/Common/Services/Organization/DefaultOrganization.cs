using VulWall.Dashboard.Common.Services.ScanSchedule;
using VulWall.Dashboard.Data.Entities.Organization;
using VulWall.Dashboard.Data.Repositories;
using OrgEntity = VulWall.Dashboard.Data.Entities.Organization.Organization;

namespace VulWall.Dashboard.Common.Services.Organization;

/// <summary>
/// A self-hosted install has exactly one organization. The web app creates it at startup;
/// the scanner only reads it (scan schedule from subscription_settings.scan_cron).
/// </summary>
public static class DefaultOrganization
{
    public const string DefaultName = "My Organization";

    /// <summary>The single organization, or null before <see cref="EnsureExistsAsync"/> ran.</summary>
    public static async Task<OrgEntity?> GetAsync(OrganizationRepository repository) =>
        (await repository.FindAsync(_ => true, o => o.CreatedAt, limit: 1)).FirstOrDefault();

    public static async Task<OrgEntity> EnsureExistsAsync(OrganizationRepository repository)
    {
        var existing = await GetAsync(repository);
        if (existing != null)
            return existing;

        var now = DateTime.UtcNow;
        return await repository.CreateAsync(new OrgEntity
        {
            CompanyName = DefaultName,
            SubscriptionSettings = new SubscriptionSettings { ScanCron = ScanCronGenerator.RandomWeekly() },
            CreatedAt = now,
            UpdatedAt = now
        });
    }
}
