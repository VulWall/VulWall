using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Common.Contracts.Enums;
using MongoDB.Bson;
using MongoDB.Driver;
using Finding = VulWall.Dashboard.Data.Entities.Finding.Finding;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Reports.Models;
using VulWall.Dashboard.Reports.Services.ReportGeneration;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Reports;

/// <summary>
/// Asset A is scanned (s1), disabled for one scan (s2), then enabled again and scanned (s3).
/// The scanner skips A's finding in s2, so the report delta must not count it as resolved in
/// s2 or as new in s3. Asset C is in every scan: its fixed finding is resolved and its new
/// finding is new. Asset B is added before s3, so its finding is new in s3.
/// </summary>
[Collection(MongoCollection.Name)]
public class FindingDeltaBuilderTests(MongoFixture mongo)
{
    private const string AssetA = "asset-a";
    private const string AssetB = "asset-b";
    private const string AssetC = "asset-c";
    private static readonly DateTime S1At = DateTime.UtcNow.AddHours(-3);
    private static readonly DateTime S2At = DateTime.UtcNow.AddHours(-2);
    private static readonly DateTime S3At = DateTime.UtcNow.AddHours(-1);

    private static readonly Scan S1 = NewScan("s1", S1At, AssetA, AssetC);
    private static readonly Scan S2 = NewScan("s2", S2At, AssetC);
    private static readonly Scan S3 = NewScan("s3", S3At, AssetA, AssetB, AssetC);

    private static readonly Dictionary<string, string[]> Owners = new()
    {
        ["d-a"] = [AssetA], ["d-b"] = [AssetB], ["d-c"] = [AssetC],
    };

    private static readonly List<Finding> Findings =
    [
        NewFinding("f-a", "d-a", S1At, "s1", "s3"),
        NewFinding("f-c-fixed", "d-c", S1At, "s1"),
        NewFinding("f-c-new", "d-c", S3At, "s3"),
        NewFinding("f-b-new", "d-b", S3At, "s3"),
    ];

    private static FindingDelta Build(Scan current, Scan previous) =>
        new FindingDeltaBuilder().Build(current, previous, Findings, id => id is null ? null : Owners.GetValueOrDefault(id));

    [Fact]
    public void SkippedFinding_IsNotResolved()
    {
        var delta = Build(S2, S1);

        Assert.Equal(1, delta.Resolved);
        Assert.Equal(0, delta.New);
    }

    [Fact]
    public void SkippedFinding_IsNotNew_WhenTheAssetIsScannedAgain()
    {
        var delta = Build(S3, S2);

        // f-c-new and f-b-new (a new asset); not f-a.
        Assert.Equal(2, delta.New);
        Assert.Equal(0, delta.Resolved);
    }

    [Fact]
    public async Task SummaryReport_DoesNotCountASkippedFindingAsResolved()
    {
        var db = mongo.NewDatabase();
        var orgId = ObjectId.GenerateNewId().ToString();
        var assetA = ObjectId.GenerateNewId().ToString();
        var assetC = ObjectId.GenerateNewId().ToString();
        await db.GetCollection<BsonDocument>("organizations").InsertOneAsync(
            new BsonDocument { { "_id", ObjectId.Parse(orgId) }, { "company_name", "T" } });
        await db.GetCollection<BsonDocument>("assets").InsertManyAsync([
            new BsonDocument { { "_id", ObjectId.Parse(assetA) }, { "org_id", orgId }, { "type", "domain" }, { "enabled", true }, { "domain", "a.com" } },
            new BsonDocument { { "_id", ObjectId.Parse(assetC) }, { "org_id", orgId }, { "type", "domain" }, { "enabled", true }, { "domain", "c.com" } },
        ]);
        await db.GetCollection<BsonDocument>("scans").InsertManyAsync([
            ScanDoc(orgId, "s1", S1At, assetA, assetC), ScanDoc(orgId, "s2", S2At, assetC)]);
        await db.GetCollection<BsonDocument>("discoveries").InsertManyAsync([
            new BsonDocument { { "_id", "d-a" }, { "org_id", orgId }, { "asset_type", "domain" }, { "domain", "a.com" }, { "asset_ids", new BsonArray { assetA } } },
            new BsonDocument { { "_id", "d-c" }, { "org_id", orgId }, { "asset_type", "domain" }, { "domain", "c.com" }, { "asset_ids", new BsonArray { assetC } } },
        ]);
        await db.GetCollection<BsonDocument>("findings").InsertManyAsync([
            FindingDoc(orgId, "f-a", "d-a", "s1"),
            FindingDoc(orgId, "f-c", "d-c", "s1", "s2"),
        ]);
        var controller = new TestServices(db, orgId).ReportsController();

        var summary = Assert.IsType<SummaryReportViewModel>(Assert.IsType<ViewResult>(await controller.Summary("s2")).Model);

        Assert.Equal(0, summary.FindingDelta.Resolved);
    }

    private static Scan NewScan(string id, DateTime at, params string[] targets) => new()
    {
        Id = id,
        OrgId = "org-1",
        Status = ScanStatus.Done,
        CreatedAt = at,
        StartedAt = at,
        TargetedAssets = targets.Select(t => new TargetedAsset { AssetId = t, Type = "domain", Value = t }).ToList(),
    };

    private static Finding NewFinding(string id, string discoveryId, DateTime firstDetected, params string[] scanIds) => new()
    {
        Id = id,
        OrgId = "org-1",
        DiscoveryId = discoveryId,
        ScanIds = [.. scanIds],
        FirstDetected = firstDetected,
        LastDetected = firstDetected,
    };

    private static BsonDocument ScanDoc(string orgId, string id, DateTime at, params string[] targets) => new()
    {
        { "_id", id }, { "org_id", orgId }, { "status", "done" }, { "type", "scheduled" },
        { "created_at", at }, { "updated_at", at }, { "started_at", at }, { "completed_at", at },
        { "targeted_assets", new BsonArray(targets.Select(t => new BsonDocument { { "asset_id", t }, { "type", "domain" }, { "value", t } })) },
    };

    private static BsonDocument FindingDoc(string orgId, string id, string discoveryId, params string[] scanIds) => new()
    {
        { "_id", id }, { "org_id", orgId }, { "discovery_id", discoveryId }, { "scan_ids", new BsonArray(scanIds) },
        { "severity", "high" }, { "title", id }, { "description", "" }, { "finding_type", "type-" + id }, { "source", "nuclei" },
        { "status", "open" }, { "first_detected", S1At }, { "last_detected", S1At },
    };
}
