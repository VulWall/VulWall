namespace VulWall.Dashboard.Common.Services.ScanSchedule;

/// <summary>
/// Generates the scan schedule for a new organization. The scanner's scan coordinator reads
/// it from <c>organizations.scan_settings.scan_cron</c>.
/// </summary>
public static class ScanCronGenerator
{
    private static readonly int[] WeekendNights = [0, 5, 6]; // Sunday, Friday, Saturday

    /// <summary>
    /// Weekly scan at a random minute between 00:00 and 05:59 UTC on a random weekend night,
    /// so that many organizations on one scanner do not all start at the same moment.
    /// </summary>
    public static string RandomWeekly(Random? random = null)
    {
        var rng = random ?? Random.Shared;
        var minute = rng.Next(0, 60);
        var hour = rng.Next(0, 6);
        var dayOfWeek = WeekendNights[rng.Next(WeekendNights.Length)];
        return $"{minute} {hour} * * {dayOfWeek}";
    }
}
