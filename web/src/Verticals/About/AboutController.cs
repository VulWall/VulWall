using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.About.Services;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.About;

/// <summary>Data for the About dialog, opened from the sidebar (Common/Views/_AboutDialog.cshtml).</summary>
[Authorize]
public class AboutController(AboutService aboutService, UpdateCheckService updateCheckService) : Controller
{
    [HttpGet("/about/info")]
    public async Task<IActionResult> Info() =>
        Json(await aboutService.GetAsync(ServiceSettings.Instance.Version, DateTime.UtcNow));

    // POST (with antiforgery) because it makes an outbound request; only the dialog's button calls it.
    [HttpPost("/about/check-updates")]
    public async Task<IActionResult> CheckUpdates(CancellationToken ct) =>
        Json(await updateCheckService.CheckAsync(ServiceSettings.Instance.Version, ct));
}
