using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Assets.Models;
using VulWall.Dashboard.Assets.Services;

namespace VulWall.Dashboard.Assets;

[Authorize]
public class AssetsController(AssetsService assetsService) : Controller
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

        string assetName;
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
                assetName = asset!.Domain!;
                break;
            }
            case AssetType.Ip:
            {
                var (asset, error) = await assetsService.CreateIpAssetAsync(input.IpAddress!);
                if (error != null)
                {
                    ModelState.AddModelError(nameof(input.IpAddress), error);
                    return View(input);
                }
                assetName = asset!.Ip!;
                break;
            }
            default:
                ModelState.AddModelError(string.Empty, "Invalid asset type.");
                return View(input);
        }

        // Adding an asset never starts a scan: scans run from "Scan now" or the schedule. The
        // confirmation offers "Scan now" unless a scan is already queued or running.
        TempData["AssetAdded"] = assetName;
        TempData["AssetAddedScanState"] = (await assetsService.GetAssetAddedScanStateAsync()).ToString();
        return RedirectToAction(nameof(Index));
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
            // 409 with the message: the page calls this with fetch and shows the text.
            return Conflict(errorMessage);
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
            // 409 with the message: the page calls this with fetch, which would follow a
            // redirect to a 200 and remove the row although nothing was deleted.
            if (error != null)
                return Conflict(error);
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