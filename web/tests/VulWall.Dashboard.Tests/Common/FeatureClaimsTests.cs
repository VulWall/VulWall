using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace VulWall.Dashboard.Tests.Common;

/// <summary>
/// The UI must not promise features this app does not have: no alerts or notifications, no
/// real-time or continuous monitoring (scans run on a schedule).
/// </summary>
public sealed class FeatureClaimsTests
{
    private static readonly Regex Claim = new(
        @"real-?time|notification|vulnerability alerts|continuous (external )?monitoring|""Continuous""",
        RegexOptions.IgnoreCase);

    [Fact]
    public void ViewsAndScriptsDoNotPromiseMissingFeatures()
    {
        var src = SourceRoot();
        var files = Directory.EnumerateFiles(Path.Combine(src, "Verticals"), "*.*", SearchOption.AllDirectories)
            .Concat(Directory.EnumerateFiles(Path.Combine(src, "Common", "Views"), "*.cshtml", SearchOption.AllDirectories))
            .Concat(Directory.EnumerateFiles(Path.Combine(src, "wwwroot", "js"), "*.js", SearchOption.AllDirectories))
            .Where(f => f.EndsWith(".cshtml") || f.EndsWith(".js") || f.EndsWith(".cs"));

        var offenders = files
            .SelectMany(f => File.ReadLines(f).Select((line, i) => (f, i, line)))
            .Where(x => Claim.IsMatch(x.line))
            .Select(x => $"{Path.GetRelativePath(src, x.f)}:{x.i + 1}: {x.line.Trim()}")
            .ToList();
        Assert.Empty(offenders);
    }

    private static string SourceRoot([CallerFilePath] string thisFile = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(thisFile)!, "..", "..", "..", "src"));
}
