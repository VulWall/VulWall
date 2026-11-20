using MongoDB.Bson;
using VulWall.Dashboard.Recommendations.Services;

namespace VulWall.Dashboard.Tests.Recommendations;

public class ReferenceUrlTests
{
    [Fact]
    public void ExtractReferenceUrls_Array_ReturnsHttpLinksOnly()
    {
        var metadata = new BsonDocument("reference", new BsonArray
        {
            "https://owasp.org/x",
            "http://example.com/advisory",
            "javascript:alert(1)",
            "ftp://example.com/file",
            "not a url",
            BsonNull.Value,
            42
        });

        Assert.Equal(["https://owasp.org/x", "http://example.com/advisory"],
            RecommendationsService.ExtractReferenceUrls(metadata));
    }

    [Fact]
    public void ExtractReferenceUrls_SingleString_IsAccepted() =>
        Assert.Equal(["https://nvd.nist.gov/vuln/detail/CVE-2024-1"],
            RecommendationsService.ExtractReferenceUrls(
                new BsonDocument("reference", " https://nvd.nist.gov/vuln/detail/CVE-2024-1 ")));

    [Fact]
    public void ExtractReferenceUrls_LegacyReferencesKey_IsAccepted() =>
        Assert.Single(RecommendationsService.ExtractReferenceUrls(
            new BsonDocument("references", new BsonArray { "https://example.com" })));

    [Fact]
    public void ExtractReferenceUrls_NullOrMissing_ReturnsEmpty()
    {
        Assert.Empty(RecommendationsService.ExtractReferenceUrls(null));
        Assert.Empty(RecommendationsService.ExtractReferenceUrls(new BsonDocument("reference", BsonNull.Value)));
        Assert.Empty(RecommendationsService.ExtractReferenceUrls(new BsonDocument("other", "https://x.test")));
    }

    [Fact]
    public void ExtractReferenceUrls_DeduplicatesAndCaps()
    {
        var urls = new BsonArray(Enumerable.Range(0, 20).Select(i => $"https://example.com/{i}"))
        {
            "https://example.com/0"
        };

        var result = RecommendationsService.ExtractReferenceUrls(new BsonDocument("reference", urls));

        Assert.Equal(10, result.Count);
        Assert.Equal(result.Distinct().Count(), result.Count);
    }
}
