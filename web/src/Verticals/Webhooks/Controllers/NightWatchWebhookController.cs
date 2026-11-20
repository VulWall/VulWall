using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Common.Services.RateLimiter;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Webhooks.Models;
using VulWall.Dashboard.Webhooks.Services;

namespace VulWall.Dashboard.Webhooks.Controllers;

[AllowAnonymous]
[IgnoreAntiforgeryToken]
[Route("api/webhooks/nightwatch")]
[ApiController]
public class NightWatchWebhookController(
    NightWatchWebhookService webhookService,
    IpRateLimiterService rateLimiter,
    ILogger<NightWatchWebhookController> logger) : ControllerBase
{
    private const string RateLimitEndpoint = "webhook:nightwatch";

    [HttpPost("scan-completed")]
    public async Task<IActionResult> ScanCompleted()
    {
        if (rateLimiter.IsRateLimited(RateLimitEndpoint))
        {
            logger.LogWarning("Rate limited webhook attempt");
            return StatusCode(429);
        }

        var sharedSecret = ServiceSettings.Instance.NightWatchWebhookSecret;
        if (string.IsNullOrWhiteSpace(sharedSecret))
        {
            logger.LogWarning("NightWatch webhook secret is not configured");
            return Unauthorized();
        }

        // Buffer the body so it can be read once for HMAC and once for JSON deserialization.
        Request.EnableBuffering();
        var bodyBytes = await ReadBodyBytesAsync();

        var providedSignature = Request.Headers["X-Webhook-Signature"].FirstOrDefault();
        if (!IsSignatureValid(bodyBytes, sharedSecret, providedSignature))
        {
            rateLimiter.RecordAttempt(RateLimitEndpoint);
            logger.LogWarning("Invalid webhook signature received for scan-completed");
            return Unauthorized();
        }

        var request = JsonSerializer.Deserialize<ScanCompletedRequest>(bodyBytes);
        if (request is null)
        {
            return BadRequest();
        }

        logger.LogInformation("Received scan-completed webhook for scan {ScanId}", request.ScanId);
        await webhookService.HandleScanCompletedAsync(request.ScanId);

        return Ok();
    }

    private async Task<byte[]> ReadBodyBytesAsync()
    {
        using var ms = new MemoryStream();
        await Request.Body.CopyToAsync(ms);
        Request.Body.Position = 0;
        return ms.ToArray();
    }

    private static bool IsSignatureValid(byte[] bodyBytes, string secret, string? providedHeader)
    {
        if (string.IsNullOrWhiteSpace(providedHeader) || !providedHeader.StartsWith("sha256=", StringComparison.Ordinal))
        {
            return false;
        }

        var providedHex = providedHeader["sha256=".Length..];

        // SHA-256 always produces 64 hex chars. Reject early to guarantee
        // FixedTimeEquals doesn't short-circuit on length mismatch.
        if (providedHex.Length != 64)
        {
            return false;
        }

        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var expectedBytes = HMACSHA256.HashData(keyBytes, bodyBytes);
        var expectedHex = Convert.ToHexString(expectedBytes).ToLowerInvariant();

        // Constant-time comparison prevents timing-based secret enumeration.
        var expectedEncoded = Encoding.UTF8.GetBytes(expectedHex);
        var providedEncoded = Encoding.UTF8.GetBytes(providedHex);
        return CryptographicOperations.FixedTimeEquals(expectedEncoded, providedEncoded);
    }
}
