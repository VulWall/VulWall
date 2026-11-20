using System.Globalization;
using VulWall.Dashboard.Data.Entities.Organization;
using VulWall.Dashboard.Settings.Models;

namespace VulWall.Dashboard.Settings.Services;

/// <summary>
/// Converts between the Settings schedule form and <see cref="ScanSettings"/>. The scanner runs
/// <c>scan_cron</c> in UTC, so a local day and time are shifted by the time zone's UTC offset
/// at the moment of saving. A later daylight-saving change moves the local time by one hour.
/// </summary>
public static class ScanScheduleCron
{
    private const int MinutesPerDay = 24 * 60;
    private const int MaxDayOfMonth = 28;

    /// <summary>
    /// Builds the settings to store, or returns an error message. Off keeps the current cron
    /// (with <c>enabled: false</c>) so turning the schedule on again restores it.
    /// </summary>
    public static (ScanSettings? Settings, string? Error) Build(ScanScheduleInput input, ScanSettings? current, DateTime nowUtc)
    {
        if (!Enum.IsDefined(input.Frequency))
            return (null, "Choose how often to scan.");
        if (!TryFindTimeZone(input.TimeZone, out var zone))
            return (null, "Choose a time zone from the list.");

        if (input.Frequency == ScanFrequency.Off)
            return (new ScanSettings { ScanCron = current?.ScanCron, Enabled = false, TimeZone = zone.Id }, null);

        if (!TimeOnly.TryParseExact(input.Time, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
            return (null, "Enter the time as HH:mm, for example 02:30.");

        var offset = (int)zone.GetUtcOffset(nowUtc).TotalMinutes;
        var utcMinutes = time.Hour * 60 + time.Minute - offset;
        var dayShift = (int)Math.Floor(utcMinutes / (double)MinutesPerDay);
        utcMinutes -= dayShift * MinutesPerDay;
        var (hour, minute) = (utcMinutes / 60, utcMinutes % 60);

        string cron;
        switch (input.Frequency)
        {
            case ScanFrequency.Daily:
                cron = $"{minute} {hour} * * *";
                break;
            case ScanFrequency.Weekly:
                if (!Enum.IsDefined(input.DayOfWeek))
                    return (null, "Choose a day of the week.");
                cron = $"{minute} {hour} * * {Mod((int)input.DayOfWeek + dayShift, 7)}";
                break;
            default: // Monthly
                if (input.DayOfMonth is < 1 or > MaxDayOfMonth)
                    return (null, $"Choose a day of the month from 1 to {MaxDayOfMonth}.");
                var utcDay = input.DayOfMonth + dayShift;
                if (utcDay is < 1 or > MaxDayOfMonth)
                    return (null, $"Day {input.DayOfMonth} at {input.Time} in {zone.Id} is day {(utcDay < 1 ? "0 (the previous month)" : utcDay)} in UTC. Choose a day from 2 to 27 or another time.");
                cron = $"{minute} {hour} {utcDay} * *";
                break;
        }

        return (new ScanSettings { ScanCron = cron, Enabled = true, TimeZone = zone.Id }, null);
    }

    /// <summary>
    /// The form values for stored settings, in the stored time zone. Returns
    /// <c>IsCustom = true</c> when the cron is not one the form writes (it is then shown as is).
    /// </summary>
    public static (ScanScheduleInput Input, bool IsCustom) ToInput(ScanSettings? settings, DateTime nowUtc)
    {
        var zone = TryFindTimeZone(settings?.TimeZone, out var z) ? z : TimeZoneInfo.Utc;
        var enabled = settings?.Enabled ?? true;
        var parsed = Parse(settings?.ScanCron, zone, nowUtc);
        if (parsed is null)
        {
            var empty = string.IsNullOrWhiteSpace(settings?.ScanCron);
            var fallback = new ScanScheduleInput
            {
                Frequency = empty || !enabled ? ScanFrequency.Off : ScanFrequency.Weekly,
                TimeZone = zone.Id
            };
            return (fallback, !empty);
        }
        return (parsed with { Frequency = enabled ? parsed.Frequency : ScanFrequency.Off }, false);
    }

    private static ScanScheduleInput? Parse(string? cron, TimeZoneInfo zone, DateTime nowUtc)
    {
        var parts = cron?.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts is not { Length: 5 } || parts[3] != "*"
            || !int.TryParse(parts[0], out var minute) || minute is < 0 or > 59
            || !int.TryParse(parts[1], out var hour) || hour is < 0 or > 23)
            return null;

        var offset = (int)zone.GetUtcOffset(nowUtc).TotalMinutes;
        var localMinutes = hour * 60 + minute + offset;
        var dayShift = (int)Math.Floor(localMinutes / (double)MinutesPerDay);
        localMinutes -= dayShift * MinutesPerDay;
        var time = $"{localMinutes / 60:00}:{localMinutes % 60:00}";

        var (dom, dow) = (parts[2], parts[4]);
        if (dom == "*" && dow == "*")
            return new ScanScheduleInput { Frequency = ScanFrequency.Daily, Time = time, TimeZone = zone.Id };

        if (dom == "*" && int.TryParse(dow, out var weekday) && weekday is >= 0 and <= 7)
            return new ScanScheduleInput
            {
                Frequency = ScanFrequency.Weekly,
                DayOfWeek = (DayOfWeek)Mod(weekday + dayShift, 7),
                Time = time,
                TimeZone = zone.Id
            };

        if (dow == "*" && int.TryParse(dom, out var day) && day is >= 1 and <= MaxDayOfMonth
            && day + dayShift is >= 1 and <= MaxDayOfMonth)
            return new ScanScheduleInput
            {
                Frequency = ScanFrequency.Monthly,
                DayOfMonth = day + dayShift,
                Time = time,
                TimeZone = zone.Id
            };

        return null;
    }

    public static bool TryFindTimeZone(string? id, out TimeZoneInfo zone)
    {
        zone = TimeZoneInfo.Utc;
        if (string.IsNullOrWhiteSpace(id))
            return false;
        if (id == TimeZoneInfo.Utc.Id)
            return true;
        if (!TimeZoneInfo.TryFindSystemTimeZoneById(id, out var found))
            return false;
        zone = found;
        return true;
    }

    private static int Mod(int value, int modulus) => ((value % modulus) + modulus) % modulus;
}
