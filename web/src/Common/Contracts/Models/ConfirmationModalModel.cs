namespace VulWall.Dashboard.Common.Contracts.Models;

/// <summary>
/// Model for reusable confirmation modal partial
/// </summary>
public class ConfirmationModalModel
{
    /// <summary>
    /// Unique ID for the modal element (required)
    /// </summary>
    public string ModalId { get; set; } = string.Empty;

    /// <summary>
    /// Modal title text (required)
    /// </summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Main message/question text (required)
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Text for the confirm button (required)
    /// </summary>
    public string ConfirmButtonText { get; set; } = "Confirm";

    /// <summary>
    /// Text for the cancel button (optional, defaults to "Cancel")
    /// </summary>
    public string? CancelButtonText { get; set; }

    /// <summary>
    /// Bootstrap button style for confirm button: "primary", "danger", "warning", "success", "info" (optional, defaults to "primary")
    /// </summary>
    public string? ConfirmButtonStyle { get; set; }

    /// <summary>
    /// Icon class for confirm button (optional, e.g., "fas fa-check")
    /// </summary>
    public string? ConfirmButtonIcon { get; set; }

    /// <summary>
    /// Modal size: "default", "large", "small" (optional, defaults to "large")
    /// </summary>
    public string? Size { get; set; } = "large";

    /// <summary>
    /// Center the modal vertically (optional, defaults to true)
    /// </summary>
    public bool Centered { get; set; } = true;

    /// <summary>
    /// Header style: "danger", "warning", "success", "info", or null for default (optional)
    /// </summary>
    public string? HeaderStyle { get; set; }

    /// <summary>
    /// Icon class for header (optional, e.g., "fas fa-exclamation-triangle")
    /// </summary>
    public string? Icon { get; set; }

    /// <summary>
    /// Make the message text bold (optional, defaults to false)
    /// </summary>
    public bool MessageBold { get; set; } = false;

    /// <summary>
    /// List of detail items to display in an alert box (optional)
    /// </summary>
    public List<string>? Details { get; set; }

    /// <summary>
    /// Title for the details section (optional)
    /// </summary>
    public string? DetailsTitle { get; set; }

    /// <summary>
    /// Icon for the details title (optional, e.g., "fas fa-info-circle")
    /// </summary>
    public string? DetailsIcon { get; set; }

    /// <summary>
    /// Bootstrap alert style for details: "info", "warning", "danger", "success" (optional, defaults to "info")
    /// </summary>
    public string? DetailsStyle { get; set; }

    /// <summary>
    /// Footer message displayed at the bottom of the modal body (optional)
    /// </summary>
    public string? FooterMessage { get; set; }

    /// <summary>
    /// ID for a div that can be dynamically populated with content (optional)
    /// </summary>
    public string? DynamicContentId { get; set; }

    /// <summary>
    /// Remove border from header (optional, defaults to true)
    /// </summary>
    public bool BorderlessHeader { get; set; } = true;

    /// <summary>
    /// Remove border from footer (optional, defaults to true)
    /// </summary>
    public bool BorderlessFooter { get; set; } = true;
}
