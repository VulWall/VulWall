using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Reports;
using VulWall.Dashboard.Reports.Models;

namespace VulWall.Dashboard.Tests.Reports;

/// <summary>
/// SHARED_LINKS_ENABLED is false in tests (TestEnvironment). Both gates must answer before
/// they touch any dependency, so the controller is built without them.
/// </summary>
public class SharedLinksGateTests
{
    private static ReportsController CreateController() =>
        new(null!, null!, null!, null!, null!, null!, null!, null!, null!, null!, null!, null!, null!);

    [Fact]
    public async Task CreateSharedLink_WhenSharedLinksDisabled_IsRejected()
    {
        var result = await CreateController().CreateSharedLink(new CreateSharedLinkRequest { ReportName = "r" });

        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        Assert.False(Assert.IsType<CreateSharedLinkResponse>(badRequest.Value).Success);
    }

    [Fact]
    public async Task SharedReport_WhenSharedLinksDisabled_IsNotFound()
    {
        var result = await CreateController().SharedReport("any-token");

        Assert.IsType<NotFoundResult>(result);
    }
}
