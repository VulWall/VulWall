using MongoDB.Bson;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Reports.Services.ReportGeneration;

namespace VulWall.Dashboard.Tests.Reports;

public class FindingsAggregatorReferenceTests
{
    [Fact]
    public void DetailedFindings_KeepOnlyHttpReferenceLinks()
    {
        var finding = new Finding
        {
            Id = "f1",
            Title = "Test finding",
            Severity = Severity.High,
            References = ["javascript:alert(document.cookie)", "https://nvd.nist.gov/x"],
            Metadata = new BsonDocument("reference", new BsonArray { "data:text/html,<script>1</script>", "http://example.com/a" })
        };

        var detailed = new FindingsAggregator().GetDetailedFindings([finding], Severity.High).Single();

        var urls = ((List<Dictionary<string, string>>)detailed["references"]).Select(r => r["reference_url"]);
        Assert.Equal(["https://nvd.nist.gov/x", "http://example.com/a"], urls);
    }
}
