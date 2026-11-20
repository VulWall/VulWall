using System.Linq.Expressions;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Common.Services.ScanTrigger;

public enum TriggerScanResult
{
    /// <summary>No scan was in progress: a scan is queued and starts on the scanner's next poll.</summary>
    Started,

    /// <summary>A scan is running: a follow-up scan is queued and starts right after it.</summary>
    QueuedAfterCurrent,

    /// <summary>A follow-up scan was already queued: nothing was inserted. It reads the assets
    /// when it starts, so it includes assets added since it was queued.</summary>
    AlreadyQueued
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
    /// A scan the scanner has started (pending or running) and that is younger than
    /// <see cref="InProgressWindow"/>.
    /// </summary>
    public static Expression<Func<Scan, bool>> StartedPredicate(DateTime utcNow)
    {
        var cutoff = utcNow - InProgressWindow;
        return s => (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running) && s.CreatedAt >= cutoff;
    }

    /// <summary>
    /// A scan is in progress while it is queued (waiting for the scanner), pending or running.
    /// A queued scan counts at any age: the scanner will still pick it up (for example when it
    /// was down for a day).
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
    /// Queues a scan for the current organization. While a scan runs, it queues one follow-up
    /// scan, so assets added during the run are scanned right after it instead of at the next
    /// scheduled scan. There is never more than one queued scan per organization: a second
    /// request returns <see cref="TriggerScanResult.AlreadyQueued"/>. The unique partial index
    /// on <c>scans</c> (<c>org_id</c> where <c>status</c> is <c>queued</c>, see
    /// <c>MongoDbIndexManager</c>) makes this hold for concurrent requests too.
    /// </summary>
    public async Task<TriggerScanResult> TriggerAsync(string triggeredBy)
    {
        if (await scansRepository.ExistsAsync(s => s.Status == ScanStatus.Queued))
            return TriggerScanResult.AlreadyQueued;

        var now = DateTime.UtcNow;
        var running = await scansRepository.ExistsAsync(StartedPredicate(now));

        try
        {
            await scansRepository.CreateAsync(new Scan
            {
                Status = ScanStatus.Queued,
                Type = ScanType.Requested,
                TriggeredBy = triggeredBy,
                CreatedAt = now,
                UpdatedAt = now
            });
        }
        catch (MongoWriteException e) when (e.WriteError?.Category == ServerErrorCategory.DuplicateKey)
        {
            // A concurrent request queued one first.
            return TriggerScanResult.AlreadyQueued;
        }

        return running ? TriggerScanResult.QueuedAfterCurrent : TriggerScanResult.Started;
    }
}
