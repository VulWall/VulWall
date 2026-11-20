using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Finding;
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
        doc.Add("degraded_assets", new BsonArray
        {
            new BsonDocument { { "asset_id", "a1" }, { "domain", "gone.example" }, { "reason", "root_nxdomain" } },
        });
        doc.Add("unchecked_finding_ids", new BsonArray { "f1" });

        var scan = await RoundTrip(doc);

        Assert.NotNull(scan);
        Assert.Equal("pipeline_quiescent", scan.CompletionReason);
        Assert.False(scan.FindingsReconciled);
        var degraded = Assert.Single(scan.DegradedAssets);
        Assert.Equal("a1", degraded.AssetId);
        Assert.Equal("gone.example", degraded.Domain);
        Assert.Equal(DegradedAsset.RootNxDomain, degraded.Reason);
        Assert.Equal(["f1"], scan.UncheckedFindingIds);
    }

    [Fact]
    public async Task Scan_WithoutCompletionFields_LeavesThemNull()
    {
        var scan = await RoundTrip(DoneScan("s2"));

        Assert.NotNull(scan);
        Assert.Null(scan.CompletionReason);
        Assert.Null(scan.FindingsReconciled);
        Assert.Empty(scan.DegradedAssets);
        Assert.Empty(scan.UncheckedFindingIds);
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

    [Fact]
    public void RecentRun_PartialScanHint_NamesDegradedAssetCount()
    {
        var scan = new Scan
        {
            OrgId = OrgId,
            Status = ScanStatus.Done,
            FindingsReconciled = false,
            DegradedAssets =
            [
                new DegradedAsset { AssetId = "a1", Domain = "gone.example", Reason = "root_nxdomain" },
                new DegradedAsset { AssetId = "a1", Domain = "gone.example", Reason = "dns_failures" },
                new DegradedAsset { AssetId = "a2", Domain = "flaky.example", Reason = "subdomain_enumeration_failed" },
            ],
            Stats = new ScanStats { TotalFindings = 3 },
        };

        var run = Assert.Single(ScansService.BuildLiveScanStatus([scan], []).RecentRuns);

        Assert.Equal("3 issues · partial scan", run.Meta);
        Assert.Contains("2 assets", run.MetaHint);
    }

    [Fact]
    public void RecentRun_PartialScanHint_NamesUncheckedIssueCount()
    {
        var scan = new Scan
        {
            OrgId = OrgId,
            Status = ScanStatus.Done,
            FindingsReconciled = false,
            Stats = new ScanStats { TotalFindings = 3, UncheckedFindings = 4 },
        };

        var run = Assert.Single(ScansService.BuildLiveScanStatus([scan], []).RecentRuns);

        Assert.Contains("4 open issues could not be re-checked", run.MetaHint);
    }

    [Fact]
    public async Task ScanStats_UncheckedFindings_RoundTrips()
    {
        var doc = DoneScan("s-unchecked");
        doc["stats"] = new BsonDocument { { "total_findings", 7 }, { "unchecked_findings", 5 } };

        var read = await RoundTrip(doc);

        Assert.Equal(5, read!.Stats.UncheckedFindings);
    }

    private static Finding NewFinding(string id, string title, params string[] scanIds) => new()
    {
        Id = id,
        OrgId = OrgId,
        Title = title,
        FindingType = title,
        Severity = Severity.High,
        Source = "nuclei",
        ScanIds = [.. scanIds],
    };

    [Fact]
    public void Comparison_FindingOfDegradedAsset_IsNotCheckedNotResolved()
    {
        var baseline = new Scan { Id = "s1", OrgId = OrgId, Status = ScanStatus.Done, CreatedAt = DateTime.UtcNow.AddDays(-1) };
        var latest = new Scan
        {
            Id = "s2",
            OrgId = OrgId,
            Status = ScanStatus.Done,
            FindingsReconciled = false,
            DegradedAssets = [new DegradedAsset { AssetId = "a1", Domain = "gone.example", Reason = "root_nxdomain" }],
            UncheckedFindingIds = ["f-gone"],
        };
        var findings = new[]
        {
            NewFinding("f-gone", "TLS 1.0 enabled", "s1"),
            NewFinding("f-fixed", "Exposed .git directory", "s1"),
            NewFinding("f-still", "Missing HSTS", "s1", "s2"),
        };

        var cmp = ScansService.BuildComparison(baseline, latest, findings);

        var resolved = Assert.Single(cmp.Resolved);
        Assert.Equal("Exposed .git directory", resolved.Title);
        Assert.Equal(1, cmp.ResolvedTotal);
        Assert.Equal(1, cmp.NotCheckedCount);
        Assert.Equal(1, cmp.UnchangedCount);
    }

    [Fact]
    public void Comparison_WithoutDegradedAssets_ResolvesMissingFindings()
    {
        var baseline = new Scan { Id = "s1", OrgId = OrgId, Status = ScanStatus.Done };
        var latest = new Scan { Id = "s2", OrgId = OrgId, Status = ScanStatus.Done, FindingsReconciled = true };

        var cmp = ScansService.BuildComparison(baseline, latest, [NewFinding("f1", "TLS 1.0 enabled", "s1")]);

        Assert.Equal(1, cmp.ResolvedTotal);
        Assert.Equal(0, cmp.NotCheckedCount);
    }
}
