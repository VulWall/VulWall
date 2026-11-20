using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities.Finding;

namespace VulWall.Dashboard.Common.Utils;

public static class FindingSeverityCounter
{
    public static (int Critical, int High, int Medium, int Low) CountBySeverityGrouped(
        IEnumerable<Finding> findings)
    {
        var groups = findings
            .GroupBy(f => new { FindingType = f.FindingType ?? f.Title, f.Severity, Source = f.Source ?? "" })
            .Select(g => g.Key.Severity)
            .ToList();

        return (
            Critical: groups.Count(s => s == Severity.Critical),
            High: groups.Count(s => s == Severity.High),
            Medium: groups.Count(s => s == Severity.Medium),
            Low: groups.Count(s => s == Severity.Low)
        );
    }

    public static (int Critical, int High, int Medium, int Low) CountBySeverityRaw(
        IEnumerable<Finding> findings)
    {
        var list = findings.ToList();
        return (
            Critical: list.Count(f => f.Severity == Severity.Critical),
            High: list.Count(f => f.Severity == Severity.High),
            Medium: list.Count(f => f.Severity == Severity.Medium),
            Low: list.Count(f => f.Severity == Severity.Low)
        );
    }
}
