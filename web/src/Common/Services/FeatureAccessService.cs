using VulWall.Dashboard.Common.Models;

namespace VulWall.Dashboard.Common.Services;

/// <summary>
/// Decides which features the current organization can use. Extension point: register a
/// different implementation to restrict features; the default grants everything.
/// </summary>
public interface IFeatureAccessService
{
    Task<FeatureAccess> GetFeatureAccessAsync();
}

/// <summary>
/// Default for self-hosted installs: every organization has full access, except that shared
/// report links follow the install-wide SHARED_LINKS_ENABLED setting (off by default).
/// </summary>
public sealed class FullFeatureAccessService(bool sharedLinksEnabled) : IFeatureAccessService
{
    private readonly FeatureAccess _access = FeatureAccess.Full with { CanShareReports = sharedLinksEnabled };

    public Task<FeatureAccess> GetFeatureAccessAsync() => Task.FromResult(_access);
}
