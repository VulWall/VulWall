using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using VulWall.Dashboard.Common.Services.NightWatch.Models;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Common.Services.NightWatch;

public class NightWatchService(HttpClient httpClient, ILogger<NightWatchService> logger)
{
    public async Task<TriggerScanResult> TriggerScanAsync(string orgId, string triggeredBy)
    {
        var settings = ServiceSettings.Instance;
        var baseUrl = settings.NightWatchBaseUrl;
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            logger.LogWarning("NightWatch base URL is not configured. Skipping scan trigger");
            return TriggerScanResult.Failed;
        }

        try
        {
            var payload = new TriggerScanRequest
            {
                OrgId = orgId,
                TriggeredBy = triggeredBy
            };

            var json = JsonSerializer.Serialize(payload);
            var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl.TrimEnd('/')}/api/scans")
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };

            // Attach API key when configured (required by NightWatch in production)
            var apiKey = settings.NightWatchApiKey;
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                request.Headers.Add("X-API-Key", apiKey);
            }

            var response = await httpClient.SendAsync(request);

            // NightWatch rejects a trigger while the org already has a running scan.
            if (response.StatusCode == HttpStatusCode.Conflict)
            {
                logger.LogInformation("NightWatch scan already running for org {OrgId}; trigger skipped", orgId);
                return TriggerScanResult.AlreadyRunning;
            }

            response.EnsureSuccessStatusCode();

            var result = await response.Content.ReadFromJsonAsync<TriggerScanResponse>();
            return result?.ScanId is { } scanId
                ? new TriggerScanResult(TriggerScanOutcome.Started, scanId)
                : TriggerScanResult.Failed;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to trigger NightWatch scan for org {OrgId}", orgId);
            return TriggerScanResult.Failed;
        }
    }
}
