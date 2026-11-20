using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.NightWatch;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Assets.Models;
using VulWall.Dashboard.Assets.Services;

namespace VulWall.Dashboard.Assets;

[Authorize]
public class AssetsController(
    AssetsService assetsService,
    NightWatchService nightWatchService,
    IOrganizationContext organizationContext) : Controller
{
    public async Task<IActionResult> Index()
    {
        var model = await assetsService.GetAssetsAsync();
        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> Add()
    {
        if (!await assetsService.CanAddAssetAsync())
        {
            var maxAssets = await assetsService.GetMaxAssetsAsync();
            TempData["Error"] = $"You have reached the maximum limit of {maxAssets} asset(s) for your plan. Please upgrade to add more assets.";
            return RedirectToAction(nameof(Index));
        }

        await PopulateAddViewBagAsync();
        return View(new AddAssetInput());
    }

    private async Task PopulateAddViewBagAsync()
    {
        var (used, max) = await assetsService.GetAssetUsageAsync();
        ViewBag.AssetsUsed = used;
        ViewBag.AssetsMax = max;
        ViewBag.QuickAddDomain = await assetsService.GetQuickAddDomainAsync(GetVerifiedEmailForOwnership());
    }

    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Assets, Action = "Added asset")]
    public async Task<IActionResult> Add(AddAssetInput input)
    {
        if (!await assetsService.CanAddAssetAsync())
        {
            var maxAssets = await assetsService.GetMaxAssetsAsync();
            TempData["Error"] = $"You have reached the maximum limit of {maxAssets} asset(s) for your plan. Please upgrade to add more assets.";
            return RedirectToAction(nameof(Index));
        }

        if (!ModelState.IsValid)
        {
            await PopulateAddViewBagAsync();
            return View(input);
        }

        switch (input.AssetType)
        {
            case AssetType.Domain:
            {
                var userEmail = GetVerifiedEmailForOwnership();
                var (asset, error) = await assetsService.CreateDomainAssetAsync(input.DomainName!, userEmail);
                if (error != null)
                {
                    ModelState.AddModelError(nameof(input.DomainName), error);
                    await PopulateAddViewBagAsync();
                    return View(input);
                }
                // Auto-verified (email domain matched) → scan immediately.
                // Otherwise the asset is pending: send the user to prove ownership via DNS-TXT.
                if (asset!.Enabled)
                {
                    await TriggerScanAndSetTempData(asset.Domain!);
                    return RedirectToAction(nameof(Index));
                }
                return RedirectToAction(nameof(Verify), new { id = asset.Id });
            }
            case AssetType.Ip:
            {
                var (asset, error) = await assetsService.CreateIpAssetAsync(input.IpAddress!);
                if (error != null)
                {
                    ModelState.AddModelError(nameof(input.IpAddress), error);
                    await PopulateAddViewBagAsync();
                    return View(input);
                }
                await TriggerScanAndSetTempData(asset!.Ip!);
                return RedirectToAction(nameof(Index));
            }
            default:
                ModelState.AddModelError(string.Empty, "Invalid asset type.");
                await PopulateAddViewBagAsync();
                return View(input);
        }
    }

    /// <summary>
    /// One-click add + scan for the user's verified email domain. The domain is re-derived
    /// server-side from the verified-email claim — never taken from the request body — so this
    /// endpoint cannot be used to auto-verify an arbitrary domain and bypass DNS-TXT ownership
    /// proof. The distinct audit action ("Quick-added verified domain") is the activation event
    /// we query in the auditlogs collection; keep it separate from the normal "Added asset".
    /// </summary>
    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Assets, Action = "Quick-added verified domain")]
    public async Task<IActionResult> QuickAdd()
    {
        // Failure branches invalidate ModelState so AuditLog's ShouldLogAudit skips them:
        // the "Quick-added verified domain" audit action is an activation metric and must
        // count real adds only, not limit-reached / ineligible / create-error attempts.
        if (!await assetsService.CanAddAssetAsync())
        {
            var maxAssets = await assetsService.GetMaxAssetsAsync();
            TempData["Error"] = $"You have reached the maximum limit of {maxAssets} asset(s) for your plan. Please upgrade to add more assets.";
            ModelState.AddModelError(string.Empty, "Asset limit reached.");
            return RedirectToAction(nameof(Index));
        }

        var domain = await assetsService.GetQuickAddDomainAsync(GetVerifiedEmailForOwnership());
        if (domain == null)
        {
            TempData["Error"] = "This domain isn't eligible for quick-add.";
            ModelState.AddModelError(string.Empty, "Domain not eligible for quick-add.");
            return RedirectToAction(nameof(Index));
        }

        var (asset, error) = await assetsService.CreateDomainAssetAsync(domain, GetVerifiedEmailForOwnership());
        if (error != null)
        {
            TempData["Error"] = error;
            ModelState.AddModelError(string.Empty, error);
            return RedirectToAction(nameof(Index));
        }

        await TriggerScanAndSetTempData(asset!.Domain!);
        return RedirectToAction(nameof(Index));
    }

    /// <summary>
    /// Returns the signed-in user's email only when Auth0 asserts it is verified.
    /// Ownership auto-verification trusts the email domain, so an unverified email must never
    /// grant it — an unverified address is attacker-controllable. Returning null makes
    /// <see cref="AssetsService.CreateDomainAssetAsync"/> fall back to the DNS-TXT flow (fail closed).
    /// The email_verified claim rides in the Auth0 ID token; if it is absent we also fail closed.
    /// </summary>
    private string? GetVerifiedEmailForOwnership()
    {
        var emailVerified = User.FindFirst("email_verified")?.Value;
        if (!string.Equals(emailVerified, "true", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return User.FindFirst(ClaimTypes.Email)?.Value;
    }

    private async Task TriggerScanAndSetTempData(string assetName)
    {
        if (!await assetsService.CanTriggerImmediateScanAsync())
        {
            TempData["Info"] = "Asset added successfully. It will be included in your next scheduled scan.";
            return;
        }

        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        var triggeredBy = User.FindFirst(ClaimTypes.Email)?.Value ?? "unknown";
        var scanId = await nightWatchService.TriggerScanAsync(orgId, triggeredBy);

        if (scanId != null)
        {
            TempData["ScanTriggered"] = assetName;
        }
        else
        {
            TempData["Info"] = $"Asset {assetName} has been added successfully.";
        }
    }

    [HttpGet]
    public async Task<IActionResult> Verify(string id)
    {
        var model = await assetsService.GetVerifyDomainViewModelAsync(id);
        if (model == null)
        {
            TempData["Info"] = "Only domains require verification.";
            return RedirectToAction(nameof(Index));
        }

        return View(model);
    }

    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Assets, Action = "Verified domain")]
    public async Task<IActionResult> VerifyDomain(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            TempData["Error"] = "Asset ID is required.";
            return RedirectToAction(nameof(Index));
        }

        var (success, message) = await assetsService.VerifyDomainAsync(id);

        if (success)
        {
            TempData["Info"] = message;
        }
        else
        {
            TempData["Error"] = message;
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Assets, Action = "Updated asset status")]
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
    [AuditLog(Category = AuditLogCategory.Assets, Action = "Deleted asset")]
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