using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings.Models;
using VulWall.Dashboard.Settings.Services;

namespace VulWall.Dashboard.Settings;

public class SettingsController(
    ILogger<SettingsController> logger,
    IOrganizationContext organizationContext,
    Services.SettingsService settingsService)
    : Controller
{
    [Authorize]
    public async Task<IActionResult> Index()
    {
        var organization = await GetCurrentOrganizationAsync();

        var vm = AccountUserViewModel.FromClaims(User) with
        {
            Company = organization.CompanyName,
            Industry = organization.Industry,
            Website = organization.Website,
            OwnerEmail = organization.OwnerEmail,
            OrgId = organization.Id,
            HasLogo = organization.Logo is { Length: > 0 }
        };

        return View(vm);
    }

    [Authorize]
    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Updated company information")]
    public async Task<IActionResult> UpdateCompanyInfo(string? companyName, string? industry, string? website)
    {
        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        await settingsService.UpdateCompanyInfoAsync(orgId, companyName, industry, website);

        logger.LogInformation("Updated company info for organization: {OrgId}", orgId);

        TempData["Success"] = "Company information updated successfully";
        return RedirectToAction(nameof(Index));
    }

    [Authorize]
    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Uploaded company logo")]
    public async Task<IActionResult> UploadLogo(IFormFile? logo)
    {
        if (logo == null || logo.Length == 0)
            return BadRequest("No logo file provided");

        var allowedTypes = new[] { "image/png", "image/jpeg", "image/jpg" };
        if (!allowedTypes.Contains(logo.ContentType.ToLower()))
        {
            TempData["Error"] = "Only PNG and JPG images are allowed";
            return RedirectToAction(nameof(Index));
        }

        const int maxSizeBytes = 512000; // 500KB
        if (logo.Length > maxSizeBytes)
        {
            TempData["Error"] = "Logo file size must not exceed 500KB";
            return RedirectToAction(nameof(Index));
        }

        using var memoryStream = new MemoryStream();
        await logo.CopyToAsync(memoryStream);
        var imageBytes = memoryStream.ToArray();

        // Validate magic bytes to prevent spoofed Content-Type
        var isPng = imageBytes.Length >= 4
            && imageBytes[0] == 0x89 && imageBytes[1] == 0x50
            && imageBytes[2] == 0x4E && imageBytes[3] == 0x47;
        var isJpeg = imageBytes.Length >= 3
            && imageBytes[0] == 0xFF && imageBytes[1] == 0xD8
            && imageBytes[2] == 0xFF;

        if (!isPng && !isJpeg)
        {
            TempData["Error"] = "Invalid image file. Only PNG and JPG images are allowed.";
            return RedirectToAction(nameof(Index));
        }

        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        await settingsService.UpdateLogoAsync(orgId, imageBytes);

        TempData["Success"] = "Logo uploaded successfully";
        return RedirectToAction(nameof(Index));
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> GetLogo()
    {
        var organization = await GetCurrentOrganizationAsync();

        if (organization?.Logo == null || organization.Logo.Length == 0)
            return NotFound();

        return File(organization.Logo, "image/png");
    }

    [Authorize]
    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Removed company logo")]
    public async Task<IActionResult> RemoveLogo()
    {
        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        await settingsService.RemoveLogoAsync(orgId);

        TempData["Success"] = "Logo removed successfully";
        return RedirectToAction(nameof(Index));
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> CompleteTour()
    {
        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        await settingsService.MarkTourCompletedAsync(orgId);

        return Ok();
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> ResetTour()
    {
        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        await settingsService.ResetTourAsync(orgId);

        TempData["Success"] = "Welcome tour has been reset. Visit the Dashboard to start the tour.";
        return RedirectToAction(nameof(Index));
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> GetPreferencesData()
    {
        var organization = await GetCurrentOrganizationAsync();
        return PartialView("Partials/_Preferences", organization.TourCompleted);
    }

    private async Task<Data.Entities.Organization.Organization> GetCurrentOrganizationAsync()
    {
        var organization = await organizationContext.GetCurrentOrganizationAsync();
        return organization;
    }
}