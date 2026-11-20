using System.Runtime.InteropServices;
using System.Text;
using VulWall.Dashboard.About.Models;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities.SystemInfo;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.About.Services;

/// <summary>
/// Builds the About dialog data. The copy text is meant to be pasted into a public bug report, so it
/// holds versions and counts only: never asset names, IP addresses, emails, tokens or secrets.
/// </summary>
public class AboutService(SystemInfoRepository systemInfo, AssetsRepository assets, ScansRepository scans)
{
    private const string Unknown = "unknown";
    private const int MaxValueLength = 64;

    public async Task<AboutInfo> GetAsync(string webVersion, DateTime nowUtc)
    {
        var scanner = await systemInfo.GetByIdAsync(ScannerSystemInfo.ScannerId);
        var assetCount = await assets.CountAsync(_ => true);
        var lastScan = (await scans.FindAsync(_ => true, s => s.CreatedAt, SortDirection.Descending, limit: 1))
            .FirstOrDefault();

        var templates = Clean(scanner?.NucleiTemplates);
        if (scanner?.NucleiTemplatesUpdatedAt is { } updated)
            templates += $" (updated {updated:yyyy-MM-dd})";

        var versions = new List<VersionRow>
        {
            new("VulWall web", Clean(webVersion)),
            new("VulWall scanner", Clean(scanner?.Version)),
            new("nuclei", Clean(scanner?.Nuclei)),
            new("nuclei templates", templates),
            new("testssl.sh", Clean(scanner?.TestSsl)),
            new("retire.js", Clean(scanner?.Retire)),
            new("DB-IP country database", Clean(scanner?.DbIpCountryDate)),
            new("DB-IP ASN database", Clean(scanner?.DbIpAsnDate)),
        };

        var text = new StringBuilder();
        text.AppendLine("VulWall system info");
        foreach (var row in versions)
            text.AppendLine($"{row.Label}: {row.Value}");
        text.AppendLine($"Scanner started: {FormatTime(scanner?.StartedAt)}");
        text.AppendLine($"Web runtime: {RuntimeInformation.FrameworkDescription}");
        text.AppendLine($"Web OS: {Clean(RuntimeInformation.OSDescription)} ({RuntimeInformation.OSArchitecture})");
        text.AppendLine($"Assets: {assetCount}");
        text.AppendLine($"Last scan: {DescribeScan(lastScan)}");
        text.AppendLine($"Generated: {FormatTime(nowUtc)}");

        return new AboutInfo(versions, text.ToString());
    }

    private static string DescribeScan(Data.Entities.Scan.Scan? scan)
    {
        if (scan is null)
            return "none";
        var status = scan.Status.ToString().ToLowerInvariant();
        var reason = string.IsNullOrWhiteSpace(scan.CompletionReason) ? "" : $" ({Clean(scan.CompletionReason)})";
        return $"{status}{reason}, {FormatTime(scan.CompletedAt ?? scan.CreatedAt)}";
    }

    private static string FormatTime(DateTime? t) =>
        t is { } v ? DateTime.SpecifyKind(v, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm 'UTC'") : Unknown;

    /// <summary>
    /// The scanner writes these values, so treat them as untrusted: one line, printable, bounded.
    /// Razor and textContent do the HTML encoding.
    /// </summary>
    internal static string Clean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return Unknown;
        var chars = value.Trim().Where(c => !char.IsControl(c)).Take(MaxValueLength).ToArray();
        return chars.Length == 0 ? Unknown : new string(chars);
    }
}
