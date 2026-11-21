using VulWall.Dashboard.Discoveries.Models;

namespace VulWall.Dashboard.Tests.Discoveries;

public class DiscoveryItemViewModelTests
{
    [Theory]
    [InlineData("NL", "Netherlands (NL)")]
    [InlineData(" nl ", "Netherlands (NL)")]
    [InlineData("US", "United States (US)")]
    public void CountryLabel_KnownCode_ReturnsEnglishNameAndCode(string code, string expected) =>
        Assert.Equal(expected, new DiscoveryItemViewModel { CountryCode = code }.CountryLabel);

    [Theory]
    [InlineData("ZZ", "ZZ")]        // well-formed, not a region
    [InlineData("nld", "NLD")]      // three-letter codes are not accepted
    [InlineData("en-US", "EN-US")]  // culture names are not accepted
    [InlineData("1!", "1!")]
    public void CountryLabel_UnknownCode_FallsBackToCode(string code, string expected) =>
        Assert.Equal(expected, new DiscoveryItemViewModel { CountryCode = code }.CountryLabel);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void CountryLabel_NoCode_ReturnsNull(string? code) =>
        Assert.Null(new DiscoveryItemViewModel { CountryCode = code }.CountryLabel);
}
