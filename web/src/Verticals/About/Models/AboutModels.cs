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
    /// <summary>GitHub answered with something unexpected.</summary>
    Error,
    /// <summary>GitHub has no published release yet (404).</summary>
    NoRelease,
    /// <summary>GitHub's rate limit for this server's address is used up.</summary>
    RateLimited,
    /// <summary>The request to GitHub failed or timed out.</summary>
    Unreachable
}

public sealed record UpdateCheckResult(UpdateStatus Status, string? LatestVersion = null, string? ReleaseUrl = null);
