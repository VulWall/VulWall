using System.Linq.Expressions;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Common.Services.ScanTrigger;

public enum TriggerScanResult
{
    Started,
    AlreadyRunning
}

/// <summary>
/// Requests on-demand scans. The web app never calls the scanner directly: it inserts a
/// <c>queued</c> document into <c>scans</c>, and the scanner's coordinator picks it up and
/// turns it into a running scan. MongoDB is the only link between the two.
/// </summary>
public class ScanTriggerService(ScansRepository scansRepository)
{
    /// <summary>
    /// Bound on how old a pending or running scan may be and still count as in progress, so an
    /// orphaned scan record does not block new scans forever.
    /// </summary>
    private static readonly TimeSpan InProgressWindow = TimeSpan.FromHours(24);

    /// <summary>
    /// A scan is in progress while it is queued (waiting for the scanner), pending or running.
    /// A queued scan counts at any age: the scanner will still pick it up (for example when it
    /// was down for a day), and queuing another one would only run the same scan twice.
    /// </summary>
    public static Expression<Func<Scan, bool>> InProgressPredicate(DateTime utcNow)
    {
        var cutoff = utcNow - InProgressWindow;
        return s => s.Status == ScanStatus.Queued
                    || ((s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running) && s.CreatedAt >= cutoff);
    }

    public Task<bool> IsScanInProgressAsync() =>
        scansRepository.ExistsAsync(InProgressPredicate(DateTime.UtcNow));

    /// <summary>
    /// Queues a scan for the current organization unless one is already in progress.
    /// The check-then-insert is not atomic; two concurrent requests can both queue a scan.
    /// With a single admin user this is acceptable, and the scanner handles a queued scan
    /// that arrives while another one runs.
    /// </summary>
    public async Task<TriggerScanResult> TriggerAsync(string triggeredBy)
    {
        if (await IsScanInProgressAsync())
            return TriggerScanResult.AlreadyRunning;

        var now = DateTime.UtcNow;
        await scansRepository.CreateAsync(new Scan
        {
            Status = ScanStatus.Queued,
            Type = ScanType.Requested,
            TriggeredBy = triggeredBy,
            CreatedAt = now,
            UpdatedAt = now
        });

        return TriggerScanResult.Started;
    }
}
