using Cronos;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Scans.Models;
using VulWall.Dashboard.Data.Entities.Finding;

namespace VulWall.Dashboard.Scans.Services;

public class ScansService(
    ScansRepository scansRepository,
    FindingsRepository findingsRepository,
    ScanTriggerService scanTriggerService)
{
    /// <summary>
    /// Gets the complete Index view model with all data.
    /// Fetches scans and findings once, then passes to sub-methods.
    /// </summary>
    public async Task<IndexViewModel> GetIndexViewModelAsync(string? scanCron = null)
    {
        // Fetch all scans and all findings once in parallel
        var allScansTask = scansRepository.FindAsync(
            predicate: s => true,
            orderByProperty: s => s.CreatedAt,
            sortDirection: SortDirection.Descending);
        var allFindingsTask = findingsRepository.GetAllAsync();

        await Task.WhenAll(allScansTask, allFindingsTask);

        var allScans = (await allScansTask).ToList();
        var allFindings = (await allFindingsTask).ToList();

        var statistics = new ScanOverviewStatistics
        {
            TotalScans = allScans.Count,
            DoneScans = allScans.Count(s => s.Status == ScanStatus.Done),
            RunningScans = allScans.Count(s => s.Status == ScanStatus.Running)
        };

        // Heatmap from pre-fetched data (current year only)
        var jan1 = new DateTime(DateTime.UtcNow.Year, 1, 1);
        var heatmapData = allScans
            .Where(s => s.CreatedAt >= jan1)
            .OrderBy(s => s.CreatedAt)
            .Select(scan => MapScanToStatistics(scan, allFindings))
            .ToList();

        // Pre-compute the diff of the two most recent Done scans, if available.
        // allScans is sorted newest-first, so donePair[0] = latest, donePair[1] = baseline.
        var donePair = allScans.Where(s => s.Status == ScanStatus.Done).Take(2).ToList();
        ScanComparisonViewModel? initialComparison = donePair.Count == 2
            ? BuildComparison(donePair[1], donePair[0], allFindings)
            : null;

        var scheduledDates = GetScheduledScanDates(scanCron);

        var recentDoneScanIds = allScans.Take(5).Where(s => s.Status == ScanStatus.Done).Select(s => s.Id).ToList();
        var uniqueIssueCounts = recentDoneScanIds.Count > 0
            ? ComputeUniqueIssueCounts(recentDoneScanIds, allFindings)
            : null;

        return new IndexViewModel
        {
            TotalScans = allScans.Count,
            Statistics = statistics,
            HeatmapData = heatmapData,
            ScheduledScanDates = scheduledDates,
            InitialComparison = initialComparison,
            LastScanAt = allScans.FirstOrDefault()?.CreatedAt,
            ScanNowState = EvaluateScanNowState(allScans),
            LiveScanStatus = BuildLiveScanStatus(allScans, scheduledDates, uniqueIssueCounts)
        };
    }

    // ponytail: separate light query; skips the full-collection findings load GetIndexViewModelAsync does
    public async Task<LiveScanStatusViewModel> GetLiveScanStatusAsync(string? scanCron = null)
    {
        // limit:10 — enough for 1 running scan + 5 recent rows; avoids full-collection scan on every poll
        var allScans = (await scansRepository.FindAsync(
            predicate: s => true,
            orderByProperty: s => s.CreatedAt,
            sortDirection: SortDirection.Descending,
            limit: 10)).ToList();

        var doneScanIds = allScans.Take(5).Where(s => s.Status == ScanStatus.Done).Select(s => s.Id).ToList();
        IReadOnlyDictionary<string, int>? uniqueIssueCounts = null;
        if (doneScanIds.Count > 0)
        {
            var findings = (await findingsRepository.FindAsync(
                f => f.ScanIds.Any(sid => doneScanIds.Contains(sid)))).ToList();
            uniqueIssueCounts = ComputeUniqueIssueCounts(doneScanIds, findings);
        }

        return BuildLiveScanStatus(allScans, GetScheduledScanDates(scanCron), uniqueIssueCounts);
    }

    private static LiveScanStatusViewModel BuildLiveScanStatus(
        List<Scan> allScans,
        List<string> scheduledDates,
        IReadOnlyDictionary<string, int>? uniqueIssueCounts = null)
    {
        // allScans is sorted newest-first
        var running = allScans.FirstOrDefault(s => s.Status == ScanStatus.Running);
        var recentRuns = allScans.Take(5).Select(s => new RecentRunViewModel
        {
            Date = s.Status == ScanStatus.Running ? "Now" : s.CreatedAt.ToString("MMM dd"),
            ScanTypeLabel = s.Type == ScanType.Requested ? "On-demand" : "Scheduled",
            ScanTypeIcon = s.Type == ScanType.Requested ? "fa-bolt" : "fa-clock",
            StatusTone = s.Status switch
            {
                ScanStatus.Running => "scanning",
                ScanStatus.Done    => "completed",
                ScanStatus.Failed  => "failed",
                _                  => "pending"
            },
            Meta = s.Status switch
            {
                ScanStatus.Running => "Scanning…",
                ScanStatus.Queued => "Queued",
                ScanStatus.Done => uniqueIssueCounts != null && uniqueIssueCounts.TryGetValue(s.Id, out var unique)
                    ? $"{unique} issues ({s.Stats.TotalFindings} raw)"
                    : $"{s.Stats.TotalFindings} issues",
                ScanStatus.Failed => s.StatusReason == Scan.InterruptedByRestart ? "Interrupted by restart" : "Failed",
                _ => string.Empty
            },
            IsLive = s.Status == ScanStatus.Running
        }).ToList();

        var scanNowState = EvaluateScanNowState(allScans);

        if (running is null)
        {
            var nextDate = scheduledDates.FirstOrDefault();
            string countdown = string.Empty;
            if (nextDate is not null && DateTime.TryParse(nextDate, out var next))
            {
                var diff = DateTime.SpecifyKind(next, DateTimeKind.Utc) - DateTime.UtcNow;
                if (diff > TimeSpan.Zero)
                    countdown = $"{(int)diff.TotalDays}d {diff.Hours}h";
            }
            return new LiveScanStatusViewModel { IsScanning = false, NextScanCountdown = countdown, RecentRuns = recentRuns, ScanNowState = scanNowState };
        }

        var trigger = string.IsNullOrEmpty(running.TriggeredBy) ? "automated" : $"manual · {running.TriggeredBy}";
        return new LiveScanStatusViewModel
        {
            IsScanning = true,
            StartedTime = running.CreatedAt.ToString("HH:mm"),
            Trigger = trigger,
            RecentRuns = recentRuns,
            ScanNowState = scanNowState
        };
    }

    /// <summary>
    /// Determines whether the current org may trigger an on-demand scan. Used both by the Index
    /// view (to render the button) and by the controller's POST action (as a server-side gate).
    /// Performs its own DB read so it can be called independently of the Index view model build.
    /// </summary>
    public async Task<ScanNowState> GetScanNowStateAsync()
    {
        var hasInProgress = await scanTriggerService.IsScanInProgressAsync();

        return hasInProgress ? ScanNowState.InProgress : ScanNowState.Allowed;
    }

    /// <summary>
    /// Mirrors <see cref="GetScanNowStateAsync"/> but evaluates against an already-loaded scan list
    /// (newest-first) so the Index view model build avoids a second DB round-trip.
    /// </summary>
    private static ScanNowState EvaluateScanNowState(IList<Scan> scans)
    {
        var isInProgress = ScanTriggerService.InProgressPredicate(DateTime.UtcNow).Compile();
        if (scans.Any(isInProgress))
            return ScanNowState.InProgress;

        return ScanNowState.Allowed;
    }

    /// <summary>
    /// Builds a diff between two completed scans for the on-demand compare endpoint.
    /// Returns null when either scan is missing, not org-owned, or not in the Done state.
    /// </summary>
    public async Task<ScanComparisonViewModel?> GetComparisonAsync(string fromScanId, string toScanId)
    {
        // Org-scoped repository auto-filters tenancy, so cross-org ids simply won't be returned.
        var scans = (await scansRepository.FindAsync(
            predicate: s => s.Id == fromScanId || s.Id == toScanId,
            orderByProperty: s => s.CreatedAt,
            sortDirection: SortDirection.Ascending)).ToList();

        if (scans.Count < 2)
            return null;

        var baseline = scans.First();
        var latest = scans.Last();

        if (baseline.Status != ScanStatus.Done || latest.Status != ScanStatus.Done)
            return null;

        var findings = await findingsRepository.FindAsync(
            f => f.ScanIds.Any(sid => sid == fromScanId || sid == toScanId));

        return BuildComparison(baseline, latest, findings);
    }

    private static ScanComparisonViewModel BuildComparison(Scan baseline, Scan latest, IEnumerable<Finding> allFindings)
    {
        var findings = allFindings.ToList();
        var baselineFindings = findings.Where(f => f.ScanIds.Contains(baseline.Id)).ToList();
        var latestFindings = findings.Where(f => f.ScanIds.Contains(latest.Id)).ToList();

        // Deduplicate each scan's findings by {FindingType, Severity, Source} — same key used by
        // CountBySeverityGrouped — so diff lists and band counts always measure the same thing.
        // Without this, duplicate Finding documents for the same vuln+host across scan cycles
        // would appear in the diff lists while the band counts (which dedup) stay flat.
        static string Key(Finding f) => $"{f.FindingType ?? f.Title}|{f.Severity}|{f.Source ?? ""}";

        var baselineDeduped = baselineFindings
            .Where(f => f.Severity != Severity.Info)
            .GroupBy(Key)
            .Select(g => g.First())
            .ToList();

        var latestDeduped = latestFindings
            .Where(f => f.Severity != Severity.Info)
            .GroupBy(Key)
            .Select(g => g.First())
            .ToList();

        var latestKeySet  = latestDeduped.Select(Key).ToHashSet();
        var baselineKeySet = baselineDeduped.Select(Key).ToHashSet();

        var resolved  = baselineDeduped.Where(f => !latestKeySet.Contains(Key(f))).ToList();
        var added     = latestDeduped.Where(f => !baselineKeySet.Contains(Key(f))).ToList();
        var unchanged = baselineDeduped.Count(f => latestKeySet.Contains(Key(f)));

        var (bc, bh, bm, bl) = FindingSeverityCounter.CountBySeverityGrouped(baselineFindings);
        var (lc, lh, lm, ll) = FindingSeverityCounter.CountBySeverityGrouped(latestFindings);

        var bands = new List<SeverityBandDelta>
        {
            new() { Name = "Critical", From = bc, To = lc, Delta = lc - bc, Worsened = lc > bc },
            new() { Name = "High",     From = bh, To = lh, Delta = lh - bh, Worsened = lh > bh },
            new() { Name = "Medium",   From = bm, To = lm, Delta = lm - bm, Worsened = lm > bm },
            new() { Name = "Low",      From = bl, To = ll, Delta = ll - bl, Worsened = ll > bl },
        };

        var baselineTotal = bc + bh + bm + bl;
        var latestTotal = lc + lh + lm + ll;
        var net = latestTotal - baselineTotal;
        var pct = baselineTotal > 0 ? (int)Math.Round(Math.Abs(net) / (double)baselineTotal * 100) : 0;

        return new ScanComparisonViewModel
        {
            BaselineScanId = baseline.Id,
            LatestScanId = latest.Id,
            BaselineDate = baseline.CreatedAt.ToString("MMM dd, yyyy"),
            LatestDate = latest.CreatedAt.ToString("MMM dd, yyyy"),
            BaselineTime = $"{baseline.CreatedAt:HH:mm} · {(string.IsNullOrEmpty(baseline.TriggeredBy) ? "automated" : baseline.TriggeredBy)}",
            LatestTime = $"{latest.CreatedAt:HH:mm} · {(string.IsNullOrEmpty(latest.TriggeredBy) ? "automated" : latest.TriggeredBy)}",
            BaselineTotal = baselineTotal,
            LatestTotal = latestTotal,
            Net = net,
            PctChange = pct,
            Improved = net < 0,
            NoChange = resolved.Count == 0 && added.Count == 0,
            Bands = bands,
            Resolved = resolved.Take(6).Select(MapToDiffFinding).ToList(),
            Added = added.Take(6).Select(MapToDiffFinding).ToList(),
            ResolvedTotal = resolved.Count,
            AddedTotal = added.Count,
            UnchangedCount = unchanged,
        };
    }

    private static DiffFinding MapToDiffFinding(Finding f) => new()
    {
        Severity = f.Severity.ToString(),
        Title = f.Title,
        Host = f.Source ?? string.Empty,
    };

    private static ScanStatistics MapScanToStatistics(Scan scan, IEnumerable<Finding> allFindings)
    {
        var scanFindings = allFindings.Where(f => f.ScanIds.Contains(scan.Id)).ToList();
        var (critical, high, medium, low) = FindingSeverityCounter.CountBySeverityGrouped(scanFindings);

        return new ScanStatistics
        {
            // Only Done scans are valid comparison targets; non-Done cells become unselectable
            ScanId = scan.Status == ScanStatus.Done ? scan.Id : string.Empty,
            Date = scan.CreatedAt.ToString("yyyy-MM-dd"),
            ScanType = scan.Type.ToString(),
            Critical = critical,
            High = high,
            Medium = medium,
            Low = low
        };
    }

    private static Dictionary<string, int> ComputeUniqueIssueCounts(IEnumerable<string> scanIds, IEnumerable<Finding> findings)
    {
        var findingsList = findings.ToList();
        return scanIds.ToDictionary(
            id => id,
            id =>
            {
                var (c, h, m, l) = FindingSeverityCounter.CountBySeverityGrouped(
                    findingsList.Where(f => f.ScanIds.Contains(id)));
                return c + h + m + l;
            });
    }

    private static List<string> GetScheduledScanDates(string? scanCron)
    {
        if (string.IsNullOrWhiteSpace(scanCron))
            return [];

        try
        {
            var expression = CronExpression.Parse(scanCron);
            var dates = new List<string>();
            var now = DateTime.UtcNow;
            var endOfYear = new DateTime(now.Year, 12, 31, 23, 59, 59, DateTimeKind.Utc);

            var nextOccurrence = expression.GetNextOccurrence(now, TimeZoneInfo.Utc);
            while (nextOccurrence.HasValue && nextOccurrence.Value <= endOfYear)
            {
                dates.Add(nextOccurrence.Value.ToString("yyyy-MM-dd"));
                nextOccurrence = expression.GetNextOccurrence(nextOccurrence.Value, TimeZoneInfo.Utc);
            }

            return dates.Distinct().ToList();
        }
        catch
        {
            return [];
        }
    }
}
