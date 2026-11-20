namespace VulWall.Dashboard.Common.Models;

/// <summary>
/// Feature flags consumed by views and services. Produced by <see cref="Services.IFeatureAccessService"/>;
/// the self-hosted default grants every feature (<see cref="Full"/>).
/// </summary>
public record FeatureAccess
{
    public bool CanViewTrends { get; init; } = true;
    public bool CanShareReports { get; init; } = true;
    public bool CanPublishCertificate { get; init; } = true;
    public bool CanSuppressFindings { get; init; } = true;

    /// <summary>
    /// Every feature enabled.
    /// </summary>
    public static FeatureAccess Full { get; } = new();
}
