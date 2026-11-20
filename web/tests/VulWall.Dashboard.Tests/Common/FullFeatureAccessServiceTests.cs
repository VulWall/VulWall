using VulWall.Dashboard.Common.Services;

namespace VulWall.Dashboard.Tests.Common;

public class FullFeatureAccessServiceTests
{
    [Fact]
    public async Task GetFeatureAccessAsync_SharedLinksEnabled_GrantsEveryFeature()
    {
        var access = await new FullFeatureAccessService(sharedLinksEnabled: true).GetFeatureAccessAsync();

        Assert.True(access.CanViewTrends);
        Assert.True(access.CanShareReports);
        Assert.True(access.CanSuppressFindings);
    }

    [Fact]
    public async Task GetFeatureAccessAsync_SharedLinksDisabled_DeniesOnlySharing()
    {
        var access = await new FullFeatureAccessService(sharedLinksEnabled: false).GetFeatureAccessAsync();

        Assert.False(access.CanShareReports);
        Assert.True(access.CanViewTrends);
        Assert.True(access.CanSuppressFindings);
    }
}
