using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Dashboard.Services;

namespace VulWall.Dashboard.Dashboard;

[Authorize]
public class DashboardController(
    DashboardService dashboardService)
    : Controller
{
    public async Task<IActionResult> Index()
    {
        var model = await dashboardService.GetIndexViewModelAsync();
        return View(model);
    }
}