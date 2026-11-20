namespace VulWall.Dashboard.Extensions;

public static class DateTimeExtensions
{
    /// <summary>
    /// Converts a DateTime to a human-readable relative time string (e.g., "2 hours ago", "just now")
    /// </summary>
    public static string ToRelativeTime(this DateTime dateTime)
    {
        var timeSpan = DateTime.UtcNow - dateTime;

        if (timeSpan.TotalMinutes < 1) return "just now";
        if (timeSpan.TotalMinutes < 60) return $"{(int)timeSpan.TotalMinutes} minutes ago";
        if (timeSpan.TotalHours < 24) return $"{(int)timeSpan.TotalHours} hours ago";
        if (timeSpan.TotalDays < 7) return $"{(int)timeSpan.TotalDays} days ago";
        if (timeSpan.TotalDays < 30) return $"{(int)(timeSpan.TotalDays / 7)} weeks ago";

        return dateTime.ToString("MMM dd, yyyy");
    }
}
