using VulWall.Dashboard.Assets.Services;

namespace VulWall.Dashboard.Tests.Assets;

/// <summary>
/// The web app's copy of the scanner's discovery ids must give the same id for the same input.
/// These vectors come from the Go code (scanner/src/internal/shared/ids.go); the scanner's
/// TestDiscoveryIDGoldenVectors holds the same ones. Change both together.
/// </summary>
public class DiscoveryIdsTests
{
    private const string Org = "65f0c0ffee0000000000abcd";

    [Theory]
    [InlineData("example.com", "c750680d-fe91-5c52-871d-d2751c65d19d")]
    [InlineData(" Example.COM ", "c750680d-fe91-5c52-871d-d2751c65d19d")]
    public void Domain_MatchesTheScanner(string domain, string id) =>
        Assert.Equal(id, DiscoveryIds.Domain(Org, domain));

    [Theory]
    [InlineData("api.example.com", "5dbd06f6-a96c-52c2-9d3a-3f979ee58a22")]
    [InlineData(" API.Example.com ", "5dbd06f6-a96c-52c2-9d3a-3f979ee58a22")]
    [InlineData("example.co.uk", "6ac63044-880f-552b-a23d-ce54cb86db1d")]
    public void Subdomain_MatchesTheScanner(string subdomain, string id) =>
        Assert.Equal(id, DiscoveryIds.Subdomain(Org, subdomain));

    [Theory]
    [InlineData("203.0.113.7", "940e7b5d-6133-51a7-97f6-eeddda89bd0d")]
    [InlineData(" 203.0.113.7 ", "940e7b5d-6133-51a7-97f6-eeddda89bd0d")]
    [InlineData("2001:DB8::1", "8133bac8-3893-5e76-9dd1-ef57a074e319")] // case kept, as in Go
    public void Ip_MatchesTheScanner(string ip, string id) =>
        Assert.Equal(id, DiscoveryIds.Ip(Org, ip));

    [Fact]
    public void Ids_AreOrgScoped() =>
        Assert.Equal("1f0f89da-6576-5075-884c-73d154cc6be6", DiscoveryIds.Domain("org-2", "example.com"));

    // Go's net.IP.String() for the same input (the scanner stores DNS-found addresses so).
    [Theory]
    [InlineData("8.8.8.8", "8.8.8.8")]
    [InlineData(" 8.8.8.8 ", "8.8.8.8")]
    [InlineData("::ffff:8.8.8.8", "8.8.8.8")]
    [InlineData("::FFFF:808:808", "8.8.8.8")]
    [InlineData("2001:DB8::1", "2001:db8::1")]
    [InlineData("2001:0db8:0:0:0:0:0:1", "2001:db8::1")]
    [InlineData("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1")]
    [InlineData("2001:db8:0:1:0:0:0:1", "2001:db8:0:1::1")]
    [InlineData("2001:db8::", "2001:db8::")]
    [InlineData("::8.8.8.8", "::808:808")]
    [InlineData("2606:4700:4700::1111", "2606:4700:4700::1111")]
    [InlineData("2A00:1450:4001:80B::200E", "2a00:1450:4001:80b::200e")]
    [InlineData("2a00:1450:4001:080b:0000:0000:0000:200e", "2a00:1450:4001:80b::200e")]
    [InlineData("::", "::")]
    [InlineData("::1", "::1")]
    [InlineData("1:0:0:0:0:0:0:0", "1::")]
    public void CanonicalIp_MatchesGo(string input, string go) =>
        Assert.Equal(go, DiscoveryIds.CanonicalIp(input));

    // The scanner's determineDomainAssetType for an asset's own job: more than one dot is a
    // subdomain, whatever the public suffix.
    [Theory]
    [InlineData("example.com", "c750680d-fe91-5c52-871d-d2751c65d19d")]
    [InlineData("api.example.com", "5dbd06f6-a96c-52c2-9d3a-3f979ee58a22")]
    [InlineData("example.co.uk", "6ac63044-880f-552b-a23d-ce54cb86db1d")]
    public void ForDomainAsset_ClassifiesByDotCount(string host, string id) =>
        Assert.Equal(id, DiscoveryIds.ForDomainAsset(Org, host));
}
