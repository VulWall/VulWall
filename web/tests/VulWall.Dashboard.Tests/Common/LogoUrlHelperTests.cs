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
    [InlineData("Akamai Connected Cloud", "akamai")]
    [InlineData("Linode, LLC", "akamai")]
    [InlineData("Hetzner Online GmbH", "hetzner")]
    [InlineData("OVH SAS", "ovh")]
    [InlineData("The Constant Company, LLC", "vultr")]
    [InlineData("Vultr Holdings LLC", "vultr")]
    [InlineData("SCALEWAY S.A.S.", "scaleway")]
    [InlineData("Online S.A.S.", "scaleway")]
    [InlineData("Alibaba (US) Technology Co., Ltd.", "alibabacloud")]
    [InlineData("Hangzhou Alibaba Advertising Co.,Ltd.", "alibabacloud")]
    [InlineData("IBM Cloud", "ibmcloud")]
    [InlineData("International Business Machines Corporation", "ibmcloud")]
    [InlineData("IBM", "ibmcloud")]
    [InlineData("Alibaba Cloud (Singapore) Private Limited", "alibabacloud")]
    [InlineData("Scaleway SAS", "scaleway")]
    [InlineData("Vercel, Inc", "vercel")]
    [InlineData("Netlify, Inc.", "netlify")]
    [InlineData("Heroku, Inc.", "heroku")]
    [InlineData("GitHub, Inc.", "github")]
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
    [InlineData("Linode, LLC")]
    [InlineData("Hetzner Online GmbH")]
    [InlineData("OVH SAS")]
    [InlineData("The Constant Company, LLC")]
    [InlineData("SCALEWAY S.A.S.")]
    [InlineData("Alibaba (US) Technology Co., Ltd.")]
    [InlineData("International Business Machines Corporation")]
    [InlineData("Vercel, Inc")]
    [InlineData("Netlify, Inc.")]
    [InlineData("Heroku, Inc.")]
    [InlineData("GitHub, Inc.")]
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
    [InlineData("Hetzner Online GmbH")]  // mapped, but no file in this test web root
    [InlineData("Leaseweb Netherlands B.V.")]
    [InlineData("../../appsettings")]
    [InlineData(null)]
    public void CloudLogo_MissingOrUnsafe_ReturnsNull(string? provider) =>
        Assert.Null(LogoUrlHelper.GetCloudProviderLogoUrl(_webRoot, provider));

    [Theory]
    [InlineData("../../etc/passwd", "etc-passwd")]
    [InlineData("Leaseweb Netherlands B.V.", "leaseweb-netherlands-b-v")]
    [InlineData("Deutsche Telekom AG", "deutsche-telekom-ag")]
    // Real DB-IP ASN names that contain a provider name inside another word
    [InlineData("Politechnika Warszawska", "politechnika-warszawska")]
    [InlineData("AMAZONET TELECOM LTDA", "amazonet-telecom-ltda")]
    [InlineData("GTnet sp.j. Tomasz Gajewski Grzegorz Mazurek", "gtnet-sp-j-tomasz-gajewski-grzegorz-mazurek")]
    [InlineData("FIBMESH IN LIMITED", "fibmesh-in-limited")]
    [InlineData("LTD SibMediaFon", "ltd-sibmediafon")]
    [InlineData("Vultric Hosting", "vultric-hosting")]
    [InlineData("Alibaba Travel Company (LTD)", "alibaba-travel-company-ltd")]
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
