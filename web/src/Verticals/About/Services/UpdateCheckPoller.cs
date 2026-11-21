using VulWall.Dashboard.Common.Services.UpdateCheck;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.About.Services;

/// <summary>
/// Checks GitHub for a newer release shortly after start, then every 6 hours, and stores the result in
/// <see cref="UpdateCheckState"/> for the sidebar and the About dialog. Does nothing when UPDATE_CHECK=false.
/// A failed check is retried after 15 minutes, doubling up to the 6-hour interval, and keeps the last answer.
/// </summary>
public class UpdateCheckPoller(
    IServiceScopeFactory scopeFactory,
    UpdateCheckState state,
    TimeProvider time,
    ILogger<UpdateCheckPoller> logger) : BackgroundService
{
    public static readonly TimeSpan StartDelay = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan Interval = TimeSpan.FromHours(6);
    public static readonly TimeSpan FirstRetry = TimeSpan.FromMinutes(15);

    private int _failures;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!state.Enabled)
            return;

        var delay = StartDelay;
        while (true)
        {
            await Task.Delay(delay, time, stoppingToken);
            delay = await CheckOnceAsync(ServiceSettings.Instance.Version, stoppingToken);
        }
    }

    /// <summary>Runs one check, updates the state and returns the delay until the next check.</summary>
    internal async Task<TimeSpan> CheckOnceAsync(string currentVersion, CancellationToken ct)
    {
        UpdateCheckResult result;
        TimeSpan? rateLimitWait = null;
        try
        {
            // A new typed client per check: one HttpClient held for days would keep stale DNS.
            await using var scope = scopeFactory.CreateAsyncScope();
            var checker = scope.ServiceProvider.GetRequiredService<UpdateCheckService>();
            (result, rateLimitWait) = await checker.CheckAsync(currentVersion, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Update check failed");
            result = new UpdateCheckResult(UpdateStatus.Error);
        }

        if (!result.IsFailure)
        {
            _failures = 0;
            state.Set(result);
            return Interval;
        }

        // Keep a known answer through a network blip, so the sidebar dot does not come and go.
        if (state.Current.Status is UpdateStatus.NotChecked || state.Current.IsFailure)
            state.Set(result);

        _failures++;
        // 15 min, 30 min, 1 h, 2 h, 4 h, then the normal 6 h.
        var backoff = _failures > 5 ? Interval : FirstRetry * (1 << (_failures - 1));
        return rateLimitWait is { } wait && wait > backoff ? wait : backoff;
    }
}
