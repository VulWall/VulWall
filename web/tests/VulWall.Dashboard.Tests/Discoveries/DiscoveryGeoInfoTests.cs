using VulWall.Dashboard.Discoveries.Models;

namespace VulWall.Dashboard.Tests.Discoveries;

public sealed class DiscoveryGeoInfoTests
{
    [Fact]
    public void CdnEdge_FromScannerMetadata()
    {
        var info = DiscoveryGeoInfo.FromMetadata(new Dictionary<string, object?>
        {
            ["cdn_edge"] = "Cloudflare",
            ["waf"] = "Cloudflare"
        });

        Assert.Equal("Cloudflare", info.CdnEdge);
        Assert.Equal("Cloudflare", info.Waf);
    }

    [Fact]
    public void CdnEdge_AbsentForOwnServer() =>
        Assert.Null(DiscoveryGeoInfo.FromMetadata(new Dictionary<string, object?> { ["waf"] = "nginx" }).CdnEdge);
}
