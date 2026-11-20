using MongoDB.Bson;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.Mappers;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;

namespace VulWall.Dashboard.Reports.Services.ReportGeneration;

public class FindingsAggregator
{
    // Helper methods to safely access BsonDocument metadata
    private static string? GetMetadataString(BsonDocument? metadata, string key)
    {
        if (metadata == null || !metadata.Contains(key))
            return null;

        var value = metadata[key];
        return value.IsString ? value.AsString : null;
    }

    private static List<string>? GetMetadataArray(BsonDocument? metadata, string key)
    {
        if (metadata == null || !metadata.Contains(key))
            return null;

        var value = metadata[key];
        if (!value.IsBsonArray)
            return null;

        return value.AsBsonArray
            .Where(v => v.IsString)
            .Select(v => v.AsString)
            .ToList();
    }

    public List<Dictionary<string, object>> GetCriticalAndHighFindings(
        IEnumerable<Finding> findings,
        Dictionary<string, KnowledgeBaseEntry>? kbByType = null)
    {
        return findings
            .Where(f => f.Severity == Severity.Critical || f.Severity == Severity.High)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.FirstDetected)
            .Select(f => new Dictionary<string, object>
            {
                ["title"] = MapFindingTitle(f),
                ["affected_asset"] = GetMetadataString(f.Metadata, "matched_at")
                                     ?? "Unknown",
                ["exploitation_risk"] = DetermineExploitationRisk(f, kbByType)
            })
            .ToList();
    }

    public List<Dictionary<string, object>> GetDetailedFindings(IEnumerable<Finding> findings, Severity severity)
    {
        return findings
            .Where(f => f.Severity == severity)
            .OrderBy(f => f.FirstDetected)
            .Select(f => BuildDetailedFinding(f))
            .ToList();
    }

    private static Dictionary<string, object> BuildDetailedFinding(Finding finding)
    {
        var detailed = new Dictionary<string, object>
        {
            ["finding_id"] = finding.Id,
            ["title"] = MapFindingTitle(finding),
            ["severity"] = finding.Severity.ToString(),
            ["description"] = finding.Description
        };

        // Add affected assets
        var matchedAt = GetMetadataString(finding.Metadata, "matched_at");
        if (!string.IsNullOrEmpty(matchedAt))
        {
            detailed["affected_assets"] = new[]
            {
                new Dictionary<string, string>
                {
                    ["asset_url"] = matchedAt,
                    ["ip_address"] = ExtractIpFromMatchedAt(matchedAt)
                }
            };
        }

        // Add technical evidence from metadata
        if (finding.Metadata != null)
        {
            var evidence = BuildTechnicalEvidence(finding);
            if (!string.IsNullOrEmpty(evidence))
            {
                detailed["technical_evidence"] = evidence;
            }

            // Add references
            var references = GetMetadataArray(finding.Metadata, "reference");
            if (references?.Any() == true)
            {
                detailed["references"] = references
                    .Select(r => new Dictionary<string, string> { ["reference_url"] = r })
                    .ToList();
            }
        }

        // Wire CWE: testssl stores cwe (string), jsscanner stores cwes (array — take first)
        var cweValue = GetMetadataString(finding.Metadata, "cwe");
        if (string.IsNullOrEmpty(cweValue))
        {
            var cwesArray = GetMetadataArray(finding.Metadata, "cwes");
            cweValue = cwesArray?.FirstOrDefault();
        }
        if (!string.IsNullOrEmpty(cweValue))
        {
            detailed["cwe_id"] = cweValue; // key SummaryReportBuilder already reads
        }

        // Wire CVE: jsscanner stores cves (array — take first)
        var cvesArray = GetMetadataArray(finding.Metadata, "cves");
        var cveValue = cvesArray?.FirstOrDefault();
        if (!string.IsNullOrEmpty(cveValue))
        {
            detailed["cve_id"] = cveValue;
        }

        return detailed;
    }

    private static string MapFindingTitle(Finding finding)
    {
        if (finding.Source == "testssl")
            return TestSSLTitleMapper.MapTitle(finding.FindingType, finding.Title);

        return finding.Title;
    }

    private static string DetermineExploitationRisk(
        Finding finding,
        Dictionary<string, KnowledgeBaseEntry>? kbByType = null)
    {
        // Use KB-determined potential impact when available
        if (finding.FindingType != null && kbByType?.TryGetValue(finding.FindingType, out var kb) == true)
        {
            var kbImpact = kb.Technical?.Impact;
            if (!string.IsNullOrEmpty(kbImpact))
                return kbImpact;
        }

        // Fallback based on severity
        return finding.Severity == Severity.Critical
            ? "High exploitation risk"
            : "Moderate exploitation risk";
    }

    private static string BuildTechnicalEvidence(Finding finding)
    {
        var evidenceParts = new List<string>();

        var extractedResults = GetMetadataArray(finding.Metadata, "extracted_results");
        if (extractedResults?.Any() == true)
        {
            evidenceParts.Add($"Extracted: {string.Join(", ", extractedResults)}");
        }

        var matcherName = GetMetadataString(finding.Metadata, "matcher_name");
        if (!string.IsNullOrEmpty(matcherName))
        {
            evidenceParts.Add($"Matcher: {matcherName}");
        }

        var curlCommand = GetMetadataString(finding.Metadata, "curl_command");
        if (!string.IsNullOrEmpty(curlCommand))
        {
            evidenceParts.Add(curlCommand);
        }

        return evidenceParts.Any() ? string.Join("\n", evidenceParts) : string.Empty;
    }

    private static string ExtractIpFromMatchedAt(string matchedAt)
    {
        // Try to extract IP from formats like "104.47.160.14:443" or "https://example.com"
        if (string.IsNullOrEmpty(matchedAt))
            return "Unknown";

        // If it contains a colon, extract the part before it (likely IP:port)
        var parts = matchedAt.Split(':');
        if (parts.Length > 1 && !matchedAt.StartsWith("http"))
        {
            return parts[0];
        }

        // If it's a URL, return as-is or try to resolve
        return matchedAt.Contains("://") ? "See URL" : matchedAt;
    }
}
