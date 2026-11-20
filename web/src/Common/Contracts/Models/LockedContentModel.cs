namespace VulWall.Dashboard.Common.Contracts.Models;

/// <summary>
/// Model for the locked content partial that shows blurred content with upgrade CTA
/// </summary>
public class LockedContentModel
{
    /// <summary>
    /// Headline text explaining what's locked (e.g., "See step-by-step remediation")
    /// </summary>
    public string Headline { get; set; } = string.Empty;

    /// <summary>
    /// Optional subtext with additional context (e.g., "Fix this issue and prevent downtime")
    /// </summary>
    public string? Subtext { get; set; }

    /// <summary>
    /// Text for the upgrade button (defaults to "Upgrade to Pro")
    /// </summary>
    public string ButtonText { get; set; } = "Upgrade to Pro";

    /// <summary>
    /// Icon class for the button (defaults to "fas fa-crown")
    /// </summary>
    public string ButtonIcon { get; set; } = "fas fa-crown";

    /// <summary>
    /// Icon class for the locked indicator (defaults to "fas fa-lock")
    /// </summary>
    public string LockIcon { get; set; } = "fas fa-lock";

    /// <summary>
    /// Optional minimum height for the locked content area (e.g., "200px")
    /// </summary>
    public string? MinHeight { get; set; }

    /// <summary>
    /// Whether to show a blur effect behind the overlay (defaults to true)
    /// </summary>
    public bool ShowBlur { get; set; } = true;

    /// <summary>
    /// Optional CSS class to add to the container
    /// </summary>
    public string? ContainerClass { get; set; }

    /// <summary>
    /// Whether to show compact version (smaller padding/font)
    /// </summary>
    public bool Compact { get; set; } = false;
}
