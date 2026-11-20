using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Scans.Services;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Scans;

[Collection(MongoCollection.Name)]
public class ScanCompletionFieldsTests(MongoFixture mongo)
{
    private const string OrgId = "org-1";

    private static BsonDocument DoneScan(string id) => new()
    {
        { "_id", id },
        { "org_id", OrgId },
        { "status", "done" },
        { "type", "scheduled" },
        { "triggered_by", "system" },
        { "created_at", DateTime.UtcNow },
        { "updated_at", DateTime.UtcNow },
        { "completed_at", DateTime.UtcNow },
        { "stats", new BsonDocument { { "total_findings", 7 } } },
    };

    private async Task<Scan?> RoundTrip(BsonDocument doc)
    {
        var db = mongo.NewDatabase();
        await db.GetCollection<BsonDocument>("scans").InsertOneAsync(doc);
        var repo = new ScansRepository(db, new FixedOrganizationContext(OrgId),
            NullLogger<OrgScopedRepository<Scan, string>>.Instance);
        return await repo.GetByIdAsync(doc["_id"].AsString);
    }

    [Fact]
    public async Task Scan_WithCompletionFields_Deserializes()
    {
        var doc = DoneScan("s1");
        doc.Add("completion_reason", "pipeline_quiescent");
        doc.Add("findings_reconciled", false);
        doc.Add("degraded_reason", "dns_failures");

        var scan = await RoundTrip(doc);

        Assert.NotNull(scan);
        Assert.Equal("pipeline_quiescent", scan.CompletionReason);
        Assert.False(scan.FindingsReconciled);
        Assert.Equal("dns_failures", scan.DegradedReason);
    }

    [Fact]
    public async Task Scan_WithoutCompletionFields_LeavesThemNull()
    {
        var scan = await RoundTrip(DoneScan("s2"));

        Assert.NotNull(scan);
        Assert.Null(scan.CompletionReason);
        Assert.Null(scan.FindingsReconciled);
        Assert.Null(scan.DegradedReason);
    }

    [Theory]
    [InlineData(false, "7 issues · partial scan", true)]
    [InlineData(true, "7 issues", false)]
    [InlineData(null, "7 issues", false)]
    public void RecentRun_MarksOnlyUnreconciledScansAsPartial(bool? reconciled, string meta, bool hasHint)
    {
        var scan = new Scan
        {
            OrgId = OrgId,
            Status = ScanStatus.Done,
            FindingsReconciled = reconciled,
            Stats = new ScanStats { TotalFindings = 7 },
        };

        var run = Assert.Single(ScansService.BuildLiveScanStatus([scan], []).RecentRuns);

        Assert.Equal(meta, run.Meta);
        Assert.Equal(hasHint, run.MetaHint != null);
    }
}
