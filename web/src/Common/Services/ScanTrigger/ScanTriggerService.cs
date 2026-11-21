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

    /// <summary>A scan is queued, pending or running: nothing was inserted. "Scan now" is
    /// available again when it finishes.</summary>
    Busy
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
    /// A scan the scanner has started (pending or running) less than <see cref="InProgressWindow"/>
    /// ago. The age counts from <c>started_at</c>: a queued scan keeps its <c>created_at</c> when
    /// the scanner claims it, so a scan that waited in the queue for a day must not look stale the
    /// moment it starts. Scans without <c>started_at</c> (older scanner versions) use
    /// <c>created_at</c>. <c>started_at</c> is never earlier than <c>created_at</c>, so "either is
    /// recent" is the same as "the later one is recent", and it translates to a plain filter.
    /// </summary>
    public static Expression<Func<Scan, bool>> StartedPredicate(DateTime utcNow)
    {
        var cutoff = utcNow - InProgressWindow;
        return s => (s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running)
                    && (s.StartedAt >= cutoff || s.CreatedAt >= cutoff);
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
                    || ((s.Status == ScanStatus.Pending || s.Status == ScanStatus.Running)
                        && (s.StartedAt >= cutoff || s.CreatedAt >= cutoff));
    }

    public Task<bool> IsScanInProgressAsync() =>
        scansRepository.ExistsAsync(InProgressPredicate(DateTime.UtcNow));

    /// <summary>
    /// Queues a scan for the current organization ("Scan now"), unless a scan is already in
    /// progress (<see cref="InProgressPredicate"/>): then it inserts nothing and returns
    /// <see cref="TriggerScanResult.Busy"/>. The web app never queues a scan behind a running
    /// one; only the scanner does that, when the schedule fires during a scan. The unique partial
    /// index on <c>scans</c> (<c>org_id</c> where <c>status</c> is <c>queued</c>, see
    /// <c>MongoDbIndexManager</c>) keeps concurrent requests to one queued scan.
    /// </summary>
    public async Task<TriggerScanResult> TriggerAsync(string triggeredBy)
    {
        var now = DateTime.UtcNow;
        if (await scansRepository.ExistsAsync(InProgressPredicate(now)))
            return TriggerScanResult.Busy;

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
            return TriggerScanResult.Busy;
        }

        return TriggerScanResult.Started;
    }
}
