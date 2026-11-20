using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings.Models;
using VulWall.Dashboard.Settings.Services;

namespace VulWall.Dashboard.Settings;

public class SettingsController(
    ILogger<SettingsController> logger,
    OrganizationRepository organizationRepository,
    IOrganizationContext organizationContext,
    Services.SettingsService settingsService,
    AccountDeletionService accountDeletionService)
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

        ViewBag.StripePublishableKey = ServiceSettings.Instance.StripePublishableKey;

        return View(vm);
    }

    [Authorize]
    [HttpGet]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> GetBillingData()
    {
        var organization = await GetCurrentOrganizationAsync();
        var vm = await settingsService.GetBillingDataAsync(organization);

        ViewBag.StripePublishableKey = ServiceSettings.Instance.StripePublishableKey;
        return PartialView("Partials/_Billing", vm);
    }

    [Authorize]
    [HttpGet]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public async Task<IActionResult> GetPlansData()
    {
        var organization = await GetCurrentOrganizationAsync();
        var vm = settingsService.GetPlansData(organization);

        ViewBag.StripePublishableKey = ServiceSettings.Instance.StripePublishableKey;
        return PartialView("Partials/_Plans", vm);
    }

    [Route("/Account/Login")]
    public async Task Login(string returnUrl = "/", bool signup = false)
    {
        if (!Url.IsLocalUrl(returnUrl))
            returnUrl = "/";

        var builder = new LoginAuthenticationPropertiesBuilder()
            .WithRedirectUri(returnUrl);

        if (signup)
            builder.WithParameter("screen_hint", "signup");

        var authenticationProperties = builder.Build();

        await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
    }

    [AllowAnonymous]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Logged out")]
    public async Task Logout()
    {
        var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
            .WithRedirectUri(Url.Action("Index", "Dashboard") ?? "/")
            .Build();

        await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
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

    /// <summary>
    /// Step 1 of account deletion: generates an OTP and sends it to the owner's email.
    /// Returns 200 OK on success so the JS can switch to the OTP entry modal.
    /// </summary>
    [Authorize]
    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Requested account deletion")]
    public async Task<IActionResult> RequestAccountDeletion()
    {
        var organization = await GetCurrentOrganizationAsync();

        if (string.IsNullOrEmpty(organization.OwnerEmail))
        {
            logger.LogWarning("Account deletion requested for org {OrgId} but owner email is missing", organization.Id);
            return BadRequest("Owner email not configured for this organization.");
        }

        if (accountDeletionService.IsOtpRequestRateLimited(organization.Id))
        {
            logger.LogWarning("Account deletion OTP request rate limited for org {OrgId}", organization.Id);
            return StatusCode(429, "Please wait before requesting another verification code.");
        }

        var sent = await accountDeletionService.SendDeletionOtpAsync(organization.Id, organization.OwnerEmail);
        if (!sent)
        {
            logger.LogError("Failed to send account deletion OTP for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to send verification code. Please try again later.");
        }

        accountDeletionService.RecordOtpRequest(organization.Id);

        logger.LogInformation("Account deletion OTP sent for org {OrgId}", organization.Id);
        return Ok();
    }

    /// <summary>
    /// Step 2 of account deletion: validates the OTP and, if correct, purges all data.
    /// Returns a redirect URL — the client navigates to it, which triggers the Auth0 signout flow.
    /// Accepts the OTP from the request body — never accepts user/org IDs from client input.
    /// </summary>
    [Authorize]
    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Confirmed account deletion")]
    public async Task<IActionResult> ConfirmAccountDeletion([FromBody] ConfirmDeletionRequest request)
    {
        if (string.IsNullOrWhiteSpace(request?.Otp))
            return BadRequest("Verification code is required.");

        var orgId = await organizationContext.GetCurrentOrgIdAsync();

        // The Auth0 user ID is read exclusively from server-side claims — never from request input.
        var auth0UserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(auth0UserId))
        {
            logger.LogError("Cannot resolve Auth0 user ID from claims during account deletion for org {OrgId}", orgId);
            return StatusCode(500, "Unable to identify the authenticated user.");
        }

        var success = await accountDeletionService.ConfirmAndDeleteAccountAsync(orgId, auth0UserId, request.Otp);

        if (!success)
            return BadRequest("The verification code is invalid or has expired. Please request a new code.");

        // Data purge is complete. Return the signout URL — the client will navigate to it
        // so the Auth0 redirect chain can work correctly (it requires a full page navigation).
        return Ok(new { redirectUrl = Url.Action(nameof(SignOutAfterDeletion), "Settings") });
    }

    /// <summary>
    /// Final step of account deletion: signs the user out via Auth0 and redirects to the login page.
    /// The user's data is already gone at this point.
    /// </summary>
    [AllowAnonymous]
    public async Task SignOutAfterDeletion()
    {
        var logoutProperties = new LogoutAuthenticationPropertiesBuilder()
            .WithRedirectUri(Url.Action("Login", "Settings", new { accountDeleted = true }) ?? "/Account/Login?accountDeleted=true")
            .Build();

        await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, logoutProperties);
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    [Authorize]
    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Switched organization")]
    public async Task<IActionResult> SwitchOrg(string orgId)
    {
        if (string.IsNullOrWhiteSpace(orgId))
            return BadRequest("Organization ID is required.");

        var auth0UserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(auth0UserId))
            return Unauthorized();

        var org = await organizationRepository.GetByIdAsync(orgId);
        if (org == null || !org.UserIds.Contains(auth0UserId))
        {
            logger.LogWarning("User {UserId} attempted to switch to unauthorized org {OrgId}", auth0UserId, orgId);
            return Forbid();
        }

        HttpContext.Session.SetString("active_org_id", orgId);
        logger.LogInformation("User {UserId} switched to org {OrgId}", auth0UserId, orgId);

        return RedirectToAction("Index", "Dashboard");
    }

    private async Task<Data.Entities.Organization.Organization> GetCurrentOrganizationAsync()
    {
        var organization = await organizationContext.GetCurrentOrganizationAsync();
        return organization;
    }
}