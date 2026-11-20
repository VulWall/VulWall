using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Models;
using VulWall.Dashboard.Data.Entities.Finding;

namespace VulWall.Dashboard.Common.Utils;

public static class SecurityScoreCalculator
{
    public static class Constants
    {
        public static readonly IReadOnlyDictionary<Severity, double> SeverityWeights = new Dictionary<Severity, double>
        {
            { Severity.Critical, 40 },
            { Severity.High, 15 },
            { Severity.Medium, 5 },
            { Severity.Low, 1 },
            { Severity.Info, 0 }
        }.AsReadOnly();

        public static readonly IReadOnlyDictionary<AssetType, double> AssetMultipliers = new Dictionary<AssetType, double>
        {
            { AssetType.Domain, 1.0 },
            { AssetType.SubDomain, 0.7 },
            { AssetType.Ip, 0.5 },
            { AssetType.Port, 0.3 }
        }.AsReadOnly();

        public static readonly IReadOnlyDictionary<string, double> SourceMultipliers = new Dictionary<string, double>
        {
            { "nuclei", 1.0 },
            { "testssl", 0.6 },
            { "http-headers", 0.4 },
            { "jsscanner", 0.3 },
            { "webtechprofiler", 0.2 },
            { "email-security", 0.5 },
        }.AsReadOnly();

        public const double DefaultSourceMultiplier = 1.0;

        public const double DecayConstant = 500.0;
        public const int SingleCriticalCap = 49;
        public const int MultipleCriticalsCap = 30;
        public const int FloorNoCriticalNoHigh = 50;
        public const int FloorNoCritical = 35;
        public const int AgePenaltyThresholdDays = 7;
    }

    public class FindingGroupInput
    {
        public Severity Severity { get; set; }
        public int AssetCount { get; set; }
        public DateTime OldestFirstDetected { get; set; }
        public double AssetMultiplier { get; set; } = 1.0;
        public string Source { get; init; } = string.Empty;
        public string Title { get; set; } = string.Empty;
        public string DetailsUrl { get; set; } = "#";
    }

    public class SecurityScoreCalculation
    {
        public int Score { get; set; }
        public double TotalRisk { get; set; }
        public List<ScoreBreakdownItem> Breakdown { get; set; } = [];
        public ScoreSummary Summary { get; set; } = new();
        public ScoreCap? AppliedCap { get; set; }

        public static SecurityScoreCalculation Perfect => new()
        {
            Score = 100,
            TotalRisk = 0,
            Breakdown = [],
            Summary = new ScoreSummary
            {
                Status = "Excellent",
                Explanation = "No open vulnerabilities detected. Your security posture is excellent."
            }
        };
    }

    public static SecurityScoreCalculation Calculate(
        IReadOnlyList<FindingGroupInput> groups, DateTime referenceTime)
    {
        if (groups.Count == 0)
            return SecurityScoreCalculation.Perfect;

        var breakdown = new List<ScoreBreakdownItem>();
        double totalRisk = 0;
        var summary = new ScoreSummary();

        foreach (var group in groups)
        {
            var riskContribution = CalculateGroupRisk(
                group.Severity, group.AssetCount, group.AssetMultiplier,
                group.OldestFirstDetected, referenceTime, group.Source ?? "");
            totalRisk += riskContribution;

            var ageDays = (int)(referenceTime - group.OldestFirstDetected).TotalDays;

            var sourceMultiplier = Constants.SourceMultipliers.GetValueOrDefault(
                group.Source?.ToLowerInvariant() ?? "", Constants.DefaultSourceMultiplier);

            breakdown.Add(new ScoreBreakdownItem
            {
                Title = group.Title,
                Severity = group.Severity,
                AffectedAssetsCount = group.AssetCount,
                EstimatedScoreImpact = -(int)Math.Round(riskContribution * 100 / Constants.DecayConstant),
                AgeDays = ageDays,
                DetailsUrl = group.DetailsUrl,
                RiskContribution = riskContribution,
                Source = group.Source ?? string.Empty,
                SourceMultiplier = sourceMultiplier
            });

            switch (group.Severity)
            {
                case Severity.Critical:
                    summary.CriticalFindingTypes++;
                    break;
                case Severity.High:
                    summary.HighFindingTypes++;
                    break;
                case Severity.Medium:
                    summary.MediumFindingTypes++;
                    break;
                case Severity.Low:
                    summary.LowFindingTypes++;
                    break;
            }

            if ((group.Severity == Severity.Critical || group.Severity == Severity.High)
                && ageDays > Constants.AgePenaltyThresholdDays)
            {
                summary.AgePenalizedCount++;
            }
        }

        summary.TotalFindingTypes = groups.Count;

        // Exponential decay: rawScore = 100 * exp(-totalRisk / DecayConstant)
        var rawScore = (int)Math.Round(100 * Math.Exp(-totalRisk / Constants.DecayConstant));
        rawScore = Math.Max(0, Math.Min(100, rawScore));

        ScoreCap? appliedCap = null;
        var finalScore = rawScore;

        // Apply caps: multiple criticals -> 30, single critical -> 49
        if (summary.CriticalFindingTypes > 1 && rawScore > Constants.MultipleCriticalsCap)
        {
            appliedCap = new ScoreCap
            {
                CapValue = Constants.MultipleCriticalsCap,
                Reason = $"Multiple critical vulnerabilities present ({summary.CriticalFindingTypes} types)",
                UncappedScore = rawScore
            };
            finalScore = Constants.MultipleCriticalsCap;
        }
        else if (summary.CriticalFindingTypes == 1 && rawScore > Constants.SingleCriticalCap)
        {
            appliedCap = new ScoreCap
            {
                CapValue = Constants.SingleCriticalCap,
                Reason = "Critical vulnerability present",
                UncappedScore = rawScore
            };
            finalScore = Constants.SingleCriticalCap;
        }

        // Apply floors based on severity profile
        if (summary.CriticalFindingTypes == 0 && summary.HighFindingTypes == 0)
        {
            finalScore = Math.Max(finalScore, Constants.FloorNoCriticalNoHigh);
        }
        else if (summary.CriticalFindingTypes == 0)
        {
            finalScore = Math.Max(finalScore, Constants.FloorNoCritical);
        }

        SetScoreStatus(summary, finalScore);

        breakdown = breakdown.OrderByDescending(b => b.RiskContribution).ToList();

        return new SecurityScoreCalculation
        {
            Score = finalScore,
            TotalRisk = totalRisk,
            Breakdown = breakdown,
            Summary = summary,
            AppliedCap = appliedCap
        };
    }

    public static int CalculateScore(IReadOnlyList<FindingGroupInput> groups, DateTime referenceTime)
    {
        return Calculate(groups, referenceTime).Score;
    }

    internal static double CalculateGroupRisk(
        Severity severity, int assetCount, double assetMultiplier,
        DateTime oldestFirstDetected, DateTime referenceTime, string source = "")
    {
        var severityWeight = Constants.SeverityWeights.GetValueOrDefault(severity, 0);
        if (severityWeight == 0)
            return 0;

        var effectiveCount = Math.Max(1, assetCount);
        var assetFactor = Math.Min(2.0, Math.Log2(1 + effectiveCount));
        var ageMultiplier = GetAgeMultiplier(severity, oldestFirstDetected, referenceTime);
        var sourceMultiplier = Constants.SourceMultipliers.GetValueOrDefault(
            source?.ToLowerInvariant() ?? "", Constants.DefaultSourceMultiplier);

        return severityWeight * assetMultiplier * assetFactor * ageMultiplier * sourceMultiplier;
    }

    internal static double GetAgeMultiplier(Severity severity, DateTime firstDetected, DateTime referenceTime)
    {
        // Age penalties only apply to Critical and High severity
        if (severity != Severity.Critical && severity != Severity.High)
            return 1.0;

        var ageDays = (referenceTime - firstDetected).TotalDays;
        if (ageDays < 0) ageDays = 0;

        return ageDays switch
        {
            <= 7 => 1.0,
            <= 30 => 1.2,
            <= 90 => 1.5,
            _ => 2.0
        };
    }

    /// <summary>
    /// Returns a human-readable label for a security score based on standard thresholds.
    /// </summary>
    public static string GetScoreLabel(int score) => score switch
    {
        >= 90 => "Excellent",
        >= 70 => "Good",
        >= 50 => "Needs Attention",
        >= 30 => "Poor",
        _ => "Critical"
    };

    /// <summary>
    /// Groups findings by (FindingType, Severity, Source) and computes asset multipliers
    /// using discovery asset types. This is the standard grouping used across scoring
    /// and reports.
    /// </summary>
    public static List<FindingGroupInput> BuildFindingGroups(
        List<Finding> findings,
        Dictionary<string, AssetType> discoveryAssetTypes)
    {
        return findings
            .GroupBy(f => new { FindingType = f.FindingType ?? f.Title, f.Severity, Source = f.Source ?? "" })
            .Select(group =>
            {
                var first = group.First();
                var discoveryIds = group
                    .Select(f => f.DiscoveryId)
                    .Where(d => d != null)
                    .Distinct()
                    .ToList();

                var assetCount = discoveryIds.Count > 0 ? discoveryIds.Count : group.Count();
                var assetMultiplier = ComputeAssetMultiplier(discoveryIds!, discoveryAssetTypes);

                return new FindingGroupInput
                {
                    Severity = group.Key.Severity,
                    AssetCount = assetCount,
                    OldestFirstDetected = group.Min(f => f.FirstDetected),
                    AssetMultiplier = assetMultiplier,
                    Source = first.Source ?? "",
                    Title = first.Title,
                    DetailsUrl = "#"
                };
            })
            .ToList();
    }

    /// <summary>
    /// Computes the average asset multiplier for a set of discovery IDs based on their asset types.
    /// </summary>
    public static double ComputeAssetMultiplier(
        List<string> discoveryIds, Dictionary<string, AssetType> discoveryAssetTypes)
    {
        if (discoveryIds.Count == 0)
            return 1.0;

        var multipliers = discoveryIds
            .Where(discoveryAssetTypes.ContainsKey)
            .Select(id => Constants.AssetMultipliers.GetValueOrDefault(discoveryAssetTypes[id], 0.5))
            .ToList();

        return multipliers.Count > 0 ? multipliers.Average() : 1.0;
    }

    private static void SetScoreStatus(ScoreSummary summary, int score)
    {
        (summary.Status, summary.Explanation) = score switch
        {
            >= 90 => ("Excellent", "Your security posture is excellent with minimal risk."),
            >= 70 => ("Good", "Your security posture is good. Address remaining issues to improve."),
            >= 50 => ("Needs Attention", "Several security issues require attention."),
            >= 30 => ("Poor", "Significant security risks present. Prioritize remediation."),
            _ => ("Critical", "Critical security issues detected. Immediate action required.")
        };

        if (summary.CriticalFindingTypes > 0)
        {
            summary.Explanation = $"{summary.CriticalFindingTypes} critical vulnerability type(s) detected. " +
                                  "Address critical issues immediately to improve your score.";
        }
        else if (summary.AgePenalizedCount > 0)
        {
            summary.Explanation += $" {summary.AgePenalizedCount} issue(s) have age penalties due to delayed remediation.";
        }
    }
}
