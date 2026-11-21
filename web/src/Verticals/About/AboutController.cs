using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.About.Services;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.About;

/// <summary>Data for the About dialog, opened from the sidebar (Common/Views/_AboutDialog.cshtml).</summary>
[Authorize]
public class AboutController(AboutService aboutService) : Controller
{
    [HttpGet("/about/info")]
    public async Task<IActionResult> Info() =>
        Json(await aboutService.GetAsync(ServiceSettings.Instance.Version, DateTime.UtcNow));
}
