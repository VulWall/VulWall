using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Common.Services.ScanTrigger;
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
    ScanTriggerService scanTriggerService) : Controller
{
    public async Task<IActionResult> Index()
    {
        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        var organization = await organizationRepository.GetByIdAsync(orgId);
        var scanCron = organization?.ScanSettings?.ActiveCron;

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
        var scanCron = organization?.ScanSettings?.ActiveCron;
        var vm = await scansService.GetLiveScanStatusAsync(scanCron);
        return PartialView("Partials/_LiveScanStatus", vm);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> TriggerScan()
    {
        var state = await scansService.GetScanNowStateAsync();
        if (state != ScanNowState.Allowed)
        {
            TempData["ScanNowError"] = state.ToString();
            return RedirectToAction(nameof(Index));
        }

        var triggeredBy = User.FindFirst(ClaimTypes.Email)?.Value ?? "unknown";
        var result = await scanTriggerService.TriggerAsync(triggeredBy);

        if (result == TriggerScanResult.Started)
            TempData["ScanNowSuccess"] = "started";
        else
            TempData["ScanNowError"] = ScanNowState.InProgress.ToString();

        return RedirectToAction(nameof(Index));
    }
}
