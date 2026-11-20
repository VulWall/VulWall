namespace VulWall.Dashboard.Settings.Models;

public sealed record TimeZoneOption(string Id, string Label);

public sealed record ScanScheduleViewModel
{
    public required ScanScheduleInput Input { get; init; }

    /// <summary>The stored cron (UTC), shown as is when it is not one the form writes.</summary>
    public string? Cron { get; init; }
    public bool IsCustom { get; init; }

    /// <summary>Null when scheduled scans are off.</summary>
    public DateTime? NextScanUtc { get; init; }
    public DateTime? NextScanLocal { get; init; }

    /// <summary>True when the selected zone observes daylight saving, so the local time can move.</summary>
    public bool ZoneHasDaylightSaving { get; init; }

    public required IReadOnlyList<TimeZoneOption> TimeZones { get; init; }
}
