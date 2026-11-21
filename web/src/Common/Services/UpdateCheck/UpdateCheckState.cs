namespace VulWall.Dashboard.Common.Services.UpdateCheck;

public enum UpdateStatus
{
    /// <summary>UPDATE_CHECK=false: VulWall never asks GitHub.</summary>
    Off,
    /// <summary>The first check has not finished yet (it runs shortly after start).</summary>
    NotChecked,
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

/// <param name="LatestVersion">The latest release, always with a "v" prefix, for example "v1.2.0".</param>
/// <param name="ReleaseUrl">The release page on GitHub, built from a fixed prefix (never taken from the response).</param>
public sealed record UpdateCheckResult(UpdateStatus Status, string? LatestVersion = null, string? ReleaseUrl = null)
{
    /// <summary>The newer release to badge in the sidebar, or null when there is none to show.</summary>
    public string? AvailableVersion => Status == UpdateStatus.Available ? LatestVersion : null;

    /// <summary>Error, RateLimited or Unreachable: the check did not get an answer and is retried.</summary>
    public bool IsFailure => Status is UpdateStatus.Error or UpdateStatus.RateLimited or UpdateStatus.Unreachable;
}

/// <summary>
/// The latest update check result, written only by the background check (About vertical) and read by the
/// sidebar and the About dialog. Page loads never cause a request to GitHub.
/// </summary>
public sealed class UpdateCheckState(bool enabled)
{
    private volatile UpdateCheckResult _current = new(enabled ? UpdateStatus.NotChecked : UpdateStatus.Off);

    public bool Enabled { get; } = enabled;

    public UpdateCheckResult Current => _current;

    public void Set(UpdateCheckResult result) => _current = result;
}
