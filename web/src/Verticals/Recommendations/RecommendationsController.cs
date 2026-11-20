using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Recommendations.Constants;
using VulWall.Dashboard.Recommendations.Models;
using VulWall.Dashboard.Recommendations.Services;

namespace VulWall.Dashboard.Recommendations;

[Authorize]
public class RecommendationsController(
    ILogger<RecommendationsController> logger,
    RecommendationsService recommendationsService,
    FindingSuppressionService suppressionService,
    IFeatureAccessService featureAccessService)
    : Controller
{
    public async Task<IActionResult> Index()
    {
        try
        {
            var viewModel = await recommendationsService.GetIndexViewModelAsync();
            return View(viewModel);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error loading recommendations index");
            return View(new RecommendationsIndexViewModel());
        }
    }

    public async Task<IActionResult> Detail(string id)
    {
        try
        {
            var viewModel = await recommendationsService.GetDetailViewModelAsync(id);
            if (viewModel == null)
            {
                return NotFound();
            }

            return View(viewModel);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error loading recommendation detail for finding {FindingId}", LogSanitizer.Clean(id));
            return NotFound();
        }
    }

    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Recommendations, Action = "Suppressed finding")]
    public async Task<IActionResult> SuppressFinding(SuppressFindingInput input, string? returnFindingId = null)
    {
        var featureAccess = await featureAccessService.GetFeatureAccessAsync();
        if (!featureAccess.CanSuppressFindings)
        {
            TempData["Error"] = "Suppressing findings is not enabled.";
            if (!string.IsNullOrEmpty(returnFindingId))
                return RedirectToAction(nameof(Detail), new { id = returnFindingId });
            return RedirectToAction(nameof(Index));
        }

        if (!ModelState.IsValid)
        {
            TempData["Error"] = "Invalid input. Note must not exceed 500 characters.";
            if (!string.IsNullOrEmpty(returnFindingId))
                return RedirectToAction(nameof(Detail), new { id = returnFindingId });
            return RedirectToAction(nameof(Index));
        }

        if (string.IsNullOrEmpty(input.DiscoveryId) || string.IsNullOrEmpty(input.FindingType))
        {
            return BadRequest("DiscoveryId and FindingType are required.");
        }

        if (!SuppressionStatus.IsValid(input.Status))
        {
            return BadRequest($"Invalid suppression status '{input.Status}'.");
        }

        var suppressedBy = User.FindFirst(ClaimTypes.Email)?.Value
                           ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? "unknown";

        await suppressionService.SuppressAsync(
            input.DiscoveryId,
            input.FindingType,
            input.Status,
            suppressedBy,
            input.Note);

        TempData["Info"] = "Finding has been dismissed.";

        if (!string.IsNullOrEmpty(returnFindingId))
            return RedirectToAction(nameof(Detail), new { id = returnFindingId });

        return RedirectToAction(nameof(Index));
    }

    // Intentionally NOT gated by CanSuppressFindings: a user must always be able to
    // remove existing suppressions and restore findings to the open list.
    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Recommendations, Action = "Un-suppressed finding")]
    public async Task<IActionResult> UnsuppressFinding(UnsuppressFindingInput input, string? returnFindingId = null)
    {
        if (string.IsNullOrEmpty(input.SuppressionId))
        {
            return BadRequest("SuppressionId is required.");
        }

        await suppressionService.UnsuppressAsync(input.SuppressionId);

        TempData["Info"] = "Finding has been restored.";

        if (!string.IsNullOrEmpty(returnFindingId))
            return RedirectToAction(nameof(Detail), new { id = returnFindingId });

        return RedirectToAction(nameof(Index));
    }
}
