using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Account.Models;
using VulWall.Dashboard.Account.Services;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Services.RateLimiter;
using VulWall.Dashboard.Data.Entities.User;

namespace VulWall.Dashboard.Account;

/// <summary>
/// Local cookie authentication for self-hosted installs: first-run setup, login and logout.
/// A hosted fork that needs SSO would replace this controller and the cookie scheme
/// registration in ServiceCollectionExtensions.AddLocalAuthentication with an OIDC handler.
/// </summary>
[AllowAnonymous]
public class AccountController(
    AccountService accountService,
    IpRateLimiterService rateLimiter,
    ILogger<AccountController> logger) : Controller
{
    private const string LoginRateLimitEndpoint = "login";

    [HttpGet("/setup")]
    public async Task<IActionResult> Setup()
    {
        if (await accountService.AdminExistsAsync())
            return Redirect("/login");

        return View(new SetupInput { OrganizationName = DefaultOrganization.DefaultName });
    }

    [HttpPost("/setup")]
    public async Task<IActionResult> Setup(SetupInput input)
    {
        if (await accountService.AdminExistsAsync())
            return Redirect("/login");

        if (AccountService.ValidatePassword(input.Password) is { } passwordError)
            ModelState.AddModelError(nameof(input.Password), passwordError);

        if (!ModelState.IsValid)
            return View(input);

        var result = await accountService.CreateAdminAsync(input.Email, input.Password, input.OrganizationName);
        if (result == SetupResult.AlreadySetUp)
            return Redirect("/login");

        var user = await accountService.ValidateCredentialsAsync(input.Email, input.Password);
        await SignInAsync(user!);
        return Redirect("/");
    }

    [HttpGet("/login")]
    public async Task<IActionResult> Login(string? returnUrl = null)
    {
        if (!await accountService.AdminExistsAsync())
            return Redirect("/setup");

        if (User.Identity?.IsAuthenticated == true)
            return LocalRedirect(SafeReturnUrl(returnUrl));

        return View(new LoginInput { ReturnUrl = returnUrl });
    }

    [HttpPost("/login")]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Logged in")]
    public async Task<IActionResult> Login(LoginInput input)
    {
        if (!await accountService.AdminExistsAsync())
            return Redirect("/setup");

        if (rateLimiter.IsRateLimited(LoginRateLimitEndpoint))
        {
            logger.LogWarning("Rate-limited login attempt from {Ip}", HttpContext.Connection.RemoteIpAddress);
            ModelState.AddModelError(string.Empty, "Too many failed attempts. Try again in 15 minutes.");
            return View(input);
        }

        if (!ModelState.IsValid)
            return View(input);

        var user = await accountService.ValidateCredentialsAsync(input.Email, input.Password);
        if (user == null)
        {
            rateLimiter.RecordAttempt(LoginRateLimitEndpoint);
            ModelState.AddModelError(string.Empty, "The email or password is incorrect.");
            return View(input);
        }

        rateLimiter.ResetAttempts(LoginRateLimitEndpoint);
        await SignInAsync(user);
        return LocalRedirect(SafeReturnUrl(input.ReturnUrl));
    }

    [Authorize]
    [HttpPost("/logout")]
    [AuditLog(Category = AuditLogCategory.Account, Action = "Logged out")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/login");
    }

    private async Task SignInAsync(User user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Name, user.Email)
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));

        // The audit filter reads HttpContext.User after the action, so set it for this request too.
        HttpContext.User = principal;
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
    }

    private string SafeReturnUrl(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl) ? returnUrl : "/";
}
