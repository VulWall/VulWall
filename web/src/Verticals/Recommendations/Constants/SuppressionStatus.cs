namespace VulWall.Dashboard.Recommendations.Constants;

/// <summary>
/// Valid values for <see cref="Data.Entities.FindingSuppression.FindingSuppression.Status"/>.
/// </summary>
public static class SuppressionStatus
{
    public const string FalsePositive = "false_positive";
    public const string AcceptedRisk  = "accepted_risk";

    public static bool IsValid(string? status) =>
        status == FalsePositive || status == AcceptedRisk;
}
