using Cronos;

namespace VulWall.Dashboard.Common.Services.ScanSchedule;

public static class NextScanCalculator
{
    public record NextScan(DateTime NextUtc, DateTime PeriodStartUtc);

    /// <summary>
    /// Returns the next scheduled scan time derived from the org's cron string.
    /// Returns null when the cron is absent or unparseable.
    /// </summary>
    public static NextScan? Compute(string? cron)
    {
        if (string.IsNullOrWhiteSpace(cron))
            return null;

        try
        {
            var expr = CronExpression.Parse(cron);
            var now = DateTime.UtcNow;
            var next = expr.GetNextOccurrence(now, TimeZoneInfo.Utc);
            if (next is null)
                return null;

            // Approximate period start as (next - interval).
            // Cronos has no GetPrevious; the following occurrence gives an exact
            // interval for weekly crons and ±1 day for monthly — precise enough
            // for the progress bar fill percentage.
            var after = expr.GetNextOccurrence(next.Value, TimeZoneInfo.Utc);
            var interval = after.HasValue ? after.Value - next.Value : TimeSpan.FromDays(7);

            return new NextScan(next.Value, next.Value - interval);
        }
        catch
        {
            return null;
        }
    }
}
