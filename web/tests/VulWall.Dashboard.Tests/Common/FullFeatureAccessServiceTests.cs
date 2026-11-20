using VulWall.Dashboard.Common.Services;

namespace VulWall.Dashboard.Tests.Common;

public class FullFeatureAccessServiceTests
{
    [Fact]
    public async Task GetFeatureAccessAsync_GrantsEveryFeature()
    {
        var access = await new FullFeatureAccessService().GetFeatureAccessAsync();

        Assert.True(access.CanViewTrends);
        Assert.True(access.CanShareReports);
        Assert.True(access.CanPublishCertificate);
        Assert.True(access.CanSuppressFindings);
    }
}
