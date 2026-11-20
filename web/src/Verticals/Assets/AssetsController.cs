using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Assets.Models;
using VulWall.Dashboard.Assets.Services;

namespace VulWall.Dashboard.Assets;

[Authorize]
public class AssetsController(
    AssetsService assetsService,
    ScanTriggerService scanTriggerService) : Controller
{
    public async Task<IActionResult> Index()
    {
        var model = await assetsService.GetAssetsAsync();
        return View(model);
    }

    [HttpGet]
    public IActionResult Add()
    {
        return View(new AddAssetInput());
    }

    [HttpPost]
    public async Task<IActionResult> Add(AddAssetInput input)
    {
        if (!ModelState.IsValid)
        {
            return View(input);
        }

        switch (input.AssetType)
        {
            case AssetType.Domain:
            {
                var (asset, error) = await assetsService.CreateDomainAssetAsync(input.DomainName!);
                if (error != null)
                {
                    ModelState.AddModelError(nameof(input.DomainName), error);
                    return View(input);
                }
                await TriggerScanAndSetTempData(asset!.Domain!);
                return RedirectToAction(nameof(Index));
            }
            case AssetType.Ip:
            {
                var (asset, error) = await assetsService.CreateIpAssetAsync(input.IpAddress!);
                if (error != null)
                {
                    ModelState.AddModelError(nameof(input.IpAddress), error);
                    return View(input);
                }
                await TriggerScanAndSetTempData(asset!.Ip!);
                return RedirectToAction(nameof(Index));
            }
            default:
                ModelState.AddModelError(string.Empty, "Invalid asset type.");
                return View(input);
        }
    }

    /// <summary>
    /// Starts a scan for a newly added asset. While a scan runs, one follow-up scan is queued
    /// instead: the running scan does not pick up the new asset, the follow-up reads the assets
    /// when it starts. Adding several assets in a row queues only that one follow-up.
    /// </summary>
    private async Task TriggerScanAndSetTempData(string assetName)
    {
        var triggeredBy = User.FindFirst(ClaimTypes.Email)?.Value ?? "unknown";
        var result = await scanTriggerService.TriggerAsync(triggeredBy);

        switch (result)
        {
            case TriggerScanResult.Started:
                TempData["ScanTriggered"] = assetName;
                break;
            case TriggerScanResult.QueuedAfterCurrent:
                TempData["Info"] = $"Asset {assetName} has been added. A scan is running. Your new asset will be scanned right after it finishes.";
                break;
            default:
                TempData["Info"] = $"Asset {assetName} has been added. A follow-up scan is already queued and will include this asset.";
                break;
        }
    }

    [HttpPost]
    public async Task<IActionResult> UpdateAssetStatus(string assetId, bool enabled)
    {
        if (string.IsNullOrEmpty(assetId))
        {
            return BadRequest("Asset ID is required.");
        }

        var (success, errorMessage) = await assetsService.UpdateAssetStatusAsync(assetId, enabled);

        if (!success)
        {
            if (errorMessage!.Contains("not found"))
            {
                return NotFound(errorMessage);
            }
            return BadRequest(errorMessage);
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Delete(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest("Asset ID is required.");
        }

        var (success, error) = await assetsService.DeleteAssetAsync(id);
        if (!success)
        {
            if (error != null)
            {
                TempData["Error"] = error;
                return RedirectToAction(nameof(Index));
            }
            return NotFound($"Asset with ID {id} not found.");
        }

        TempData["Info"] = "Asset deleted successfully.";
        return RedirectToAction(nameof(Index));
    }

    [HttpGet]
    public async Task<IActionResult> GetStatistics()
    {
        var statistics = await assetsService.GetStatisticsAsync();
        return Json(statistics);
    }
}