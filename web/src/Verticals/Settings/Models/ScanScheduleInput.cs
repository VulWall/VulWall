namespace VulWall.Dashboard.Settings.Models;

public enum ScanFrequency
{
    Off,
    Daily,
    Weekly,
    Monthly
}

/// <summary>
/// The Settings "Scan schedule" form. Day and time are in <see cref="TimeZone"/>; the server
/// converts them to a UTC cron. A raw cron is never accepted from the client.
/// </summary>
public sealed record ScanScheduleInput
{
    public ScanFrequency Frequency { get; init; } = ScanFrequency.Weekly;
    public DayOfWeek DayOfWeek { get; init; } = DayOfWeek.Saturday;

    /// <summary>1–28, so the day exists in every month.</summary>
    public int DayOfMonth { get; init; } = 1;

    /// <summary>24-hour "HH:mm".</summary>
    public string Time { get; init; } = "02:00";

    /// <summary>System time zone id (IANA on Linux and macOS).</summary>
    public string TimeZone { get; init; } = "UTC";
}
