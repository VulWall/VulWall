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
/// Default for self-hosted installs: every organization has full access.
/// </summary>
public sealed class FullFeatureAccessService : IFeatureAccessService
{
    public Task<FeatureAccess> GetFeatureAccessAsync() => Task.FromResult(FeatureAccess.Full);
}
