using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Recommendations.Constants;
using VulWall.Dashboard.Recommendations.Models;
using VulWall.Dashboard.Recommendations.Services;

namespace VulWall.Dashboard.Recommendations;

[Authorize]
public class RecommendationsController(
    ILogger<RecommendationsController> logger,
    RecommendationsService recommendationsService,
    FindingSuppressionService suppressionService)
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
    public async Task<IActionResult> SuppressFinding(SuppressFindingInput input, string? returnFindingId = null)
    {

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

        var found = await suppressionService.SuppressAsync(
            input.DiscoveryId,
            input.FindingType,
            input.Status,
            suppressedBy,
            input.Note);
        if (!found)
            return NotFound();

        TempData["Info"] = "Finding has been dismissed.";

        if (!string.IsNullOrEmpty(returnFindingId))
            return RedirectToAction(nameof(Detail), new { id = returnFindingId });

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> UnsuppressFinding(UnsuppressFindingInput input, string? returnFindingId = null)
    {
        if (string.IsNullOrEmpty(input.SuppressionId))
        {
            return BadRequest("SuppressionId is required.");
        }

        if (!await suppressionService.UnsuppressAsync(input.SuppressionId))
            return NotFound();

        TempData["Info"] = "Finding has been restored.";

        if (!string.IsNullOrEmpty(returnFindingId))
            return RedirectToAction(nameof(Detail), new { id = returnFindingId });

        return RedirectToAction(nameof(Index));
    }
}
