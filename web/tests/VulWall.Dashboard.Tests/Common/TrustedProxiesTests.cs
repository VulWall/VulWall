using System.Net;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Tests.Common;

public class TrustedProxiesTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void Parse_Empty_ReturnsNoNetworks(string? value)
    {
        Assert.Empty(TrustedProxies.Parse(value));
    }

    [Fact]
    public void Parse_CidrAndBareAddresses_ReturnsNetworks()
    {
        var networks = TrustedProxies.Parse(" 10.0.0.0/8, 192.168.1.5 ,fd00::/8, ::1 ");

        Assert.Equal(4, networks.Count);
        Assert.Contains(IPNetwork.Parse("10.0.0.0/8"), networks);
        Assert.Contains(IPNetwork.Parse("192.168.1.5/32"), networks);
        Assert.Contains(IPNetwork.Parse("fd00::/8"), networks);
        Assert.Contains(IPNetwork.Parse("::1/128"), networks);
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/8,bogus")]
    public void Parse_InvalidEntry_Throws(string value)
    {
        Assert.Throws<FormatException>(() => TrustedProxies.Parse(value));
    }
}
