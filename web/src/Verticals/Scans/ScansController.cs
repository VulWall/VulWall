using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.NightWatch;
using VulWall.Dashboard.Common.Services.NightWatch.Models;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Scans.Models;
using VulWall.Dashboard.Scans.Services;

namespace VulWall.Dashboard.Scans;

[Authorize]
public class ScansController(
    ScansService scansService,
    IOrganizationContext organizationContext,
    OrganizationRepository organizationRepository,
    NightWatchService nightWatchService) : Controller
{
    public async Task<IActionResult> Index()
    {
        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        var organization = await organizationRepository.GetByIdAsync(orgId);
        var scanCron = organization?.SubscriptionSettings?.ScanCron;

        var model = await scansService.GetIndexViewModelAsync(scanCron);
        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> GetComparison(string from, string to)
    {
        if (string.IsNullOrWhiteSpace(from) || string.IsNullOrWhiteSpace(to))
            return BadRequest();

        var model = await scansService.GetComparisonAsync(from, to);
        if (model == null)
            return NotFound();

        return PartialView("Partials/_ComparisonResult", model);
    }

    [HttpGet]
    public async Task<IActionResult> LiveStatus()
    {
        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        var organization = await organizationRepository.GetByIdAsync(orgId);
        var scanCron = organization?.SubscriptionSettings?.ScanCron;
        var vm = await scansService.GetLiveScanStatusAsync(scanCron);
        return PartialView("Partials/_LiveScanStatus", vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    [AuditLog(Category = AuditLogCategory.Scans, Action = "Triggered scan")]
    public async Task<IActionResult> TriggerScan()
    {
        var state = await scansService.GetScanNowStateAsync();
        if (state != ScanNowState.Allowed)
        {
            TempData["ScanNowError"] = state.ToString();
            return RedirectToAction(nameof(Index));
        }

        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        var triggeredBy = User.FindFirst(ClaimTypes.Email)?.Value ?? "unknown";
        var result = await nightWatchService.TriggerScanAsync(orgId, triggeredBy);

        switch (result.Outcome)
        {
            case TriggerScanOutcome.Started:
                TempData["ScanNowSuccess"] = "started";
                break;
            case TriggerScanOutcome.AlreadyRunning:
                TempData["ScanNowError"] = ScanNowState.InProgress.ToString();
                break;
            default:
                TempData["ScanNowError"] = "failed";
                break;
        }

        return RedirectToAction(nameof(Index));
    }
}
