using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Reports.Services.ExecutiveSummaryJob;

/// <summary>
/// Polls MongoDB every 30 seconds for finished scans that still need an executive summary.
/// Replaces the scanner → web completion webhook: the scanner only writes the scan status.
/// </summary>
public class ExecutiveSummaryPoller(IServiceScopeFactory scopeFactory, ILogger<ExecutiveSummaryPoller> logger)
    : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var aiEnabled = !string.IsNullOrWhiteSpace(ServiceSettings.Instance.AnthropicApiKey);
        using var timer = new PeriodicTimer(Interval);

        do
        {
            try
            {
                // The processor and its repositories are scoped; this service is a singleton.
                await using var scope = scopeFactory.CreateAsyncScope();
                var processor = scope.ServiceProvider.GetRequiredService<ExecutiveSummaryProcessor>();
                var processed = await processor.ProcessPendingAsync(aiEnabled, stoppingToken);
                if (processed > 0)
                    logger.LogInformation("Executive summary poller handled {Count} scan(s)", processed);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Executive summary poll failed");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
