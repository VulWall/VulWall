using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Discoveries.Services;

namespace VulWall.Dashboard.Discoveries;

[Authorize]
public class DiscoveriesController(
    DiscoveriesService discoveriesService) : Controller
{
    public async Task<IActionResult> Index()
    {
        var model = await discoveriesService.GetIndexViewModelAsync();
        return View(model);
    }

    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Discoveries, Action = "Updated discovery ownership")]
    public async Task<IActionResult> UpdateOwnershipStatus(string discoveryId, OwnershipStatus ownershipStatus)
    {
        var success = await discoveriesService.UpdateOwnershipStatusAsync(discoveryId, ownershipStatus);

        if (!success)
        {
            if (string.IsNullOrEmpty(discoveryId))
            {
                return BadRequest("Discovery ID is required.");
            }
            return NotFound($"Discovery with ID {discoveryId} not found.");
        }

        return Ok();
    }
}