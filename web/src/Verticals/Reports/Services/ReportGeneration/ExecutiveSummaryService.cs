using System.Text.Json;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.AIServices;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;
using DbFinding = VulWall.Dashboard.Data.Entities.Finding.Finding;

namespace VulWall.Dashboard.Reports.Services.ReportGeneration;

public class ExecutiveSummaryService(
    IAIService aiService,
    ILogger<ExecutiveSummaryService> logger)
{
    private const string PromptName = "Executive_Summary_Agent";

    public async Task<string?> GenerateExecutiveSummaryAsync(
        string securityPosture,
        List<DbFinding> findings,
        Dictionary<string, KnowledgeBaseEntry>? kbByType = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var input = BuildAIInput(securityPosture, findings, kbByType);
            var inputJson = JsonSerializer.Serialize(input, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
                WriteIndented = false
            });

            var response = await aiService.GetResponseAsync(
                PromptName,
                inputJson,
                cancellationToken: cancellationToken);

            if (string.IsNullOrWhiteSpace(response))
            {
                logger.LogWarning("AI returned empty response for executive summary");
                return null;
            }

            return response.Trim();
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to generate AI executive summary");
            return null;
        }
    }

    private static ExecutiveSummaryInput BuildAIInput(
        string securityPosture,
        List<DbFinding> findings,
        Dictionary<string, KnowledgeBaseEntry>? kbByType = null)
    {
        var topFindings = findings
            .Where(f => f.Severity is Severity.Critical or Severity.High)
            .OrderByDescending(f => f.Severity)
            .Take(3)
            .Select(f =>
            {
                var kb = f.FindingType != null && kbByType?.TryGetValue(f.FindingType, out var entry) == true ? entry : null;
                return new TopFindingInput
                {
                    Title = f.Title,
                    PotentialImpact = kb?.Technical?.Impact,
                    VulnerabilityExplanation = kb?.Technical?.VulnerabilityExplanation
                };
            })
            .ToList();

        var (critical, high, medium, low) = FindingSeverityCounter.CountBySeverityGrouped(findings);
        var (rawCritical, rawHigh, rawMedium, rawLow) = FindingSeverityCounter.CountBySeverityRaw(findings);

        return new ExecutiveSummaryInput
        {
            SecurityPosture = securityPosture,
            CriticalCount = critical,
            HighCount = high,
            MediumCount = medium,
            LowCount = low,
            CriticalInstances = rawCritical,
            HighInstances = rawHigh,
            MediumInstances = rawMedium,
            LowInstances = rawLow,
            TopFindings = topFindings
        };
    }

    private class ExecutiveSummaryInput
    {
        public string SecurityPosture { get; set; } = string.Empty;
        public int CriticalCount { get; set; }
        public int HighCount { get; set; }
        public int MediumCount { get; set; }
        public int LowCount { get; set; }
        public int CriticalInstances { get; set; }
        public int HighInstances { get; set; }
        public int MediumInstances { get; set; }
        public int LowInstances { get; set; }
        public List<TopFindingInput> TopFindings { get; set; } = new();
    }

    private class TopFindingInput
    {
        public string Title { get; set; } = string.Empty;
        public string? PotentialImpact { get; set; }
        public string? VulnerabilityExplanation { get; set; }
    }
}
