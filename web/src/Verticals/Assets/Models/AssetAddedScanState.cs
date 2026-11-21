namespace VulWall.Dashboard.Assets.Models;

/// <summary>
/// What the confirmation after adding an asset offers. Adding an asset never starts a scan.
/// </summary>
public enum AssetAddedScanState
{
    /// <summary>A scan is queued or running: the new asset is in the next scan, no button.</summary>
    ScanInProgress,

    /// <summary>The organization has never had a scan: "Scan now" is the main action.</summary>
    FirstScan,

    /// <summary>Scans have run before: "Scan now" is offered next to closing the dialog.</summary>
    Idle
}
