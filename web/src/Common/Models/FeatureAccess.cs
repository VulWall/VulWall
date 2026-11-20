namespace VulWall.Dashboard.Common.Models;

/// <summary>
/// Represents feature access levels based on subscription tier.
/// Used to gate features in views and services.
/// </summary>
public record FeatureAccess
{
    /// <summary>
    /// Whether the user has an active Pro subscription
    /// </summary>
    public bool IsPro { get; init; }

    // Dashboard Features
    public bool CanViewTrends => IsPro;

    // Recommendations Features (free for all tiers)
    public bool CanViewRemediationSteps => true;
    public bool CanViewEffortEstimates => true;

    // Discoveries Features
    public bool CanAccessSubdomainDiscovery => IsPro;

    // Reports Features (technical report free for all tiers)
    public bool CanViewTechnicalReport => true;
    public bool CanShareReports => IsPro;
    public bool CanPublishCertificate => IsPro;

    // Recommendations Features
    public bool CanSuppressFindings => IsPro;

    /// <summary>
    /// Creates a FeatureAccess for the Free tier
    /// </summary>
    public static FeatureAccess Free => new() { IsPro = false };

    /// <summary>
    /// Creates a FeatureAccess for the Pro tier
    /// </summary>
    public static FeatureAccess Pro => new() { IsPro = true };
}
