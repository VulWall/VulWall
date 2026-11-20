using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace VulWall.Dashboard.Tests.Common;

/// <summary>
/// Brand rule: UPPERCASE only for the wordmark and severity band chips. Everything else
/// (eyebrows, labels, table heads) is sentence case, so no other CSS rule may uppercase text.
/// </summary>
public sealed class BrandCasingTests
{
    // Selectors that may use text-transform: uppercase.
    private static readonly HashSet<string> AllowedUppercase = [".severity-badge"];

    [Fact]
    public void OnlySeverityChipsUseUppercaseTransform()
    {
        var offenders = new List<string>();
        foreach (var file in Directory.EnumerateFiles(Path.Combine(WebRoot(), "css"), "*.css", SearchOption.AllDirectories))
        {
            var css = Regex.Replace(File.ReadAllText(file), @"/\*.*?\*/", "", RegexOptions.Singleline);
            foreach (Match rule in Regex.Matches(css, @"([^{}]+)\{([^{}]*)\}"))
            {
                if (!Regex.IsMatch(rule.Groups[2].Value, @"text-transform\s*:\s*uppercase")) continue;
                var selector = rule.Groups[1].Value.Trim();
                if (!AllowedUppercase.Contains(selector))
                    offenders.Add($"{Path.GetRelativePath(WebRoot(), file)}: {selector}");
            }
        }
        Assert.Empty(offenders);
    }

    private static string WebRoot([CallerFilePath] string thisFile = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(thisFile)!, "..", "..", "..", "src", "wwwroot"));
}
