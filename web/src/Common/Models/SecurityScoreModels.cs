using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Common.Models;

public class SecurityScoreResult
{
    public int Score { get; set; }
    public double TotalRisk { get; set; }
    public int Trend { get; set; }
    public List<ScoreBreakdownItem> Breakdown { get; set; } = [];
    public ScoreSummary Summary { get; set; } = new();
    public ScoreCap? AppliedCap { get; set; }
}

public class ScoreBreakdownItem
{
    public string Title { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public int AffectedAssetsCount { get; set; }
    public int EstimatedScoreImpact { get; set; }
    public int AgeDays { get; set; }
    public string DetailsUrl { get; set; } = "#";
    public double RiskContribution { get; set; }
    public string Source { get; set; } = string.Empty;
    public double SourceMultiplier { get; set; } = 1.0;
}

public class ScoreSummary
{
    public int CriticalFindingTypes { get; set; }
    public int HighFindingTypes { get; set; }
    public int MediumFindingTypes { get; set; }
    public int LowFindingTypes { get; set; }
    public int TotalFindingTypes { get; set; }
    public int AgePenalizedCount { get; set; }
    public string Status { get; set; } = string.Empty;
    public string Explanation { get; set; } = string.Empty;
}

public class ScoreCap
{
    public int CapValue { get; set; }
    public string Reason { get; set; } = string.Empty;
    public int UncappedScore { get; set; }
}
