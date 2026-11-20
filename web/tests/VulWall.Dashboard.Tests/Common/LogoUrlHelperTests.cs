using System.Runtime.CompilerServices;
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
        File.WriteAllBytes(Path.Combine(_root, "images", "logos", "countries", "nl.svg"), [1]);
        File.WriteAllBytes(Path.Combine(_root, "images", "logos", "cloud", "cloudflare.svg"), [1]);
        File.WriteAllBytes(Path.Combine(_root, "images", "logos", "cloud", "aws.svg"), [1]);
        _webRoot = new PhysicalFileProvider(_root);
    }

    [Theory]
    [InlineData("NL")]
    [InlineData(" nl ")]
    public void CountryFlag_ShippedFile_ReturnsLocalPath(string code) =>
        Assert.Equal("/images/logos/countries/nl.svg", LogoUrlHelper.GetCountryFlagUrl(_webRoot, code));

    [Theory]
    [InlineData("DE")]          // valid code, no file shipped
    [InlineData(null)]
    [InlineData("")]
    [InlineData("../x")]        // path traversal from scan data
    [InlineData("nld")]
    public void CountryFlag_MissingOrUnsafe_ReturnsNull(string? code) =>
        Assert.Null(LogoUrlHelper.GetCountryFlagUrl(_webRoot, code));

    [Theory]
    [InlineData("AWS", "/images/logos/cloud/aws.svg")]
    [InlineData("Cloudflare, Inc.", "/images/logos/cloud/cloudflare.svg")]
    public void CloudLogo_ShippedFile_ReturnsLocalPath(string provider, string expected) =>
        Assert.Equal(expected, LogoUrlHelper.GetCloudProviderLogoUrl(_webRoot, provider));

    [Theory]
    [InlineData("Amazon.com, Inc.", "aws")]
    [InlineData("Microsoft Corporation", "azure")]
    [InlineData("Azure", "azure")]
    [InlineData("GCP", "gcp")]
    [InlineData("Google LLC", "gcp")]
    [InlineData("Fastly, Inc.", "fastly")]
    [InlineData("DigitalOcean, LLC", "digitalocean")]
    [InlineData("Akamai Technologies, Inc.", "akamai")]
    [InlineData("Oracle Corporation", "oracle")]
    public void NormalizeProviderName_MapsKnownProviders(string input, string expected) =>
        Assert.Equal(expected, LogoUrlHelper.NormalizeProviderName(input));

    // Names the scanner's cloud detector emits (scanner/.../discovery_enrichment/cloud/sources.go)
    // plus the common ASN owners: each must resolve to a logo actually shipped in wwwroot.
    [Theory]
    [InlineData("AWS")]
    [InlineData("Azure")]
    [InlineData("GCP")]
    [InlineData("Fastly")]
    [InlineData("Cloudflare, Inc.")]
    [InlineData("DigitalOcean, LLC")]
    [InlineData("Akamai Technologies, Inc.")]
    [InlineData("Oracle Corporation")]
    public void ShippedWebRoot_HasCloudLogo(string provider)
    {
        using var webRoot = new PhysicalFileProvider(ShippedWebRootPath());
        Assert.NotNull(LogoUrlHelper.GetCloudProviderLogoUrl(webRoot, provider));
    }

    [Theory]
    [InlineData("NL")]
    [InlineData("US")]
    [InlineData("DE")]
    [InlineData("JP")]
    public void ShippedWebRoot_HasCountryFlag(string code)
    {
        using var webRoot = new PhysicalFileProvider(ShippedWebRootPath());
        Assert.Equal($"/images/logos/countries/{code.ToLowerInvariant()}.svg", LogoUrlHelper.GetCountryFlagUrl(webRoot, code));
    }

    private static string ShippedWebRootPath([CallerFilePath] string thisFile = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(thisFile)!, "..", "..", "..", "src", "wwwroot"));

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
