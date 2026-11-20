namespace VulWall.Dashboard.About.Models;

public sealed record VersionRow(string Label, string Value);

/// <summary>Data for the About dialog. <see cref="CopyText"/> is the "Copy system info" block.</summary>
public sealed record AboutInfo(IReadOnlyList<VersionRow> Versions, string CopyText);

public enum UpdateStatus
{
    /// <summary>This install runs the latest release or newer.</summary>
    Latest,
    /// <summary>A newer release exists.</summary>
    Available,
    /// <summary>This install is not a release build (for example "dev"), so it cannot be compared.</summary>
    Unknown,
    /// <summary>GitHub could not be reached or answered with something unexpected.</summary>
    Error
}

public sealed record UpdateCheckResult(UpdateStatus Status, string? LatestVersion = null, string? ReleaseUrl = null);
