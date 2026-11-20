using Microsoft.Extensions.FileProviders;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Tests.Common;

public sealed class LogoUrlHelperTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("vw-logos").FullName;
    private readonly PhysicalFileProvider _webRoot;

    public LogoUrlHelperTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "images", "logos", "countries"));
        Directory.CreateDirectory(Path.Combine(_root, "images", "logos", "cloud"));
        File.WriteAllBytes(Path.Combine(_root, "images", "logos", "countries", "nl.png"), [1]);
        File.WriteAllBytes(Path.Combine(_root, "images", "logos", "cloud", "cloudflare.png"), [1]);
        File.WriteAllBytes(Path.Combine(_root, "images", "logos", "cloud", "aws.png"), [1]);
        _webRoot = new PhysicalFileProvider(_root);
    }

    [Theory]
    [InlineData("NL")]
    [InlineData(" nl ")]
    public void CountryFlag_ShippedFile_ReturnsLocalPath(string code) =>
        Assert.Equal("/images/logos/countries/nl.png", LogoUrlHelper.GetCountryFlagUrl(_webRoot, code));

    [Theory]
    [InlineData("DE")]          // valid code, no file shipped
    [InlineData(null)]
    [InlineData("")]
    [InlineData("../x")]        // path traversal from scan data
    [InlineData("nld")]
    public void CountryFlag_MissingOrUnsafe_ReturnsNull(string? code) =>
        Assert.Null(LogoUrlHelper.GetCountryFlagUrl(_webRoot, code));

    [Theory]
    [InlineData("AWS", "/images/logos/cloud/aws.png")]
    [InlineData("Cloudflare, Inc.", "/images/logos/cloud/cloudflare.png")]
    public void CloudLogo_ShippedFile_ReturnsLocalPath(string provider, string expected) =>
        Assert.Equal(expected, LogoUrlHelper.GetCloudProviderLogoUrl(_webRoot, provider));

    [Theory]
    [InlineData("Hetzner Online GmbH")]
    [InlineData("../../appsettings")]
    [InlineData(null)]
    public void CloudLogo_MissingOrUnsafe_ReturnsNull(string? provider) =>
        Assert.Null(LogoUrlHelper.GetCloudProviderLogoUrl(_webRoot, provider));

    [Theory]
    [InlineData("../../etc/passwd", "etc-passwd")]
    [InlineData("Hetzner Online GmbH", "hetzner-online-gmbh")]
    [InlineData("  ", null)]
    public void NormalizeProviderName_ProducesSafeSlug(string input, string? expected) =>
        Assert.Equal(expected, LogoUrlHelper.NormalizeProviderName(input));

    [Fact]
    public void NoHostedAssetUrls() =>
        Assert.DoesNotContain("http", LogoUrlHelper.GetCountryFlagUrl(_webRoot, "nl"));

    public void Dispose()
    {
        _webRoot.Dispose();
        Directory.Delete(_root, recursive: true);
    }
}
