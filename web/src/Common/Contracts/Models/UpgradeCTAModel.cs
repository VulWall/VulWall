namespace VulWall.Dashboard.Common.Contracts.Models;

/// <summary>
/// Model for contextual upgrade call-to-action
/// </summary>
public class UpgradeCTAModel
{
    /// <summary>
    /// Primary text describing the benefit (e.g., "Track security trends over time")
    /// Focus on outcomes, not features
    /// </summary>
    public string Text { get; set; } = string.Empty;

    /// <summary>
    /// Button/link text (defaults to "Upgrade")
    /// </summary>
    public string ButtonText { get; set; } = "Upgrade";

    /// <summary>
    /// Icon class for the button (defaults to "fas fa-arrow-right")
    /// </summary>
    public string ButtonIcon { get; set; } = "fas fa-arrow-right";

    /// <summary>
    /// Style variant: "inline" (small link), "banner" (full-width), "card" (boxed)
    /// </summary>
    public string Style { get; set; } = "inline";

    /// <summary>
    /// Whether to show Pro badge alongside the CTA
    /// </summary>
    public bool ShowProBadge { get; set; } = true;

    /// <summary>
    /// Optional CSS class to add to the container
    /// </summary>
    public string? ContainerClass { get; set; }
}
