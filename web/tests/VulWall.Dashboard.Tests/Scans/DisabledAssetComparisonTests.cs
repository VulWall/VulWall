using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Scans;

/// <summary>
/// Asset A is scanned (s1), disabled for one scan (s2), then enabled again and scanned (s3).
/// The scanner skips A's findings in s2: they stay open and are not in s2's
/// unchecked_finding_ids. A comparison must not call them resolved (s1 to s2) or added (s2 to s3).
/// Asset C is targeted by every scan and is the control: its fixed finding is resolved and its
/// new finding is added.
/// </summary>
[Collection(MongoCollection.Name)]
public class DisabledAssetComparisonTests(MongoFixture mongo)
{
    private const string OrgId = "org-1";
    private static readonly string AssetA = ObjectId.GenerateNewId().ToString();
    private static readonly string AssetC = ObjectId.GenerateNewId().ToString();

    private async Task<TestServices> SeedAsync()
    {
        var db = mongo.NewDatabase();
        var now = DateTime.UtcNow;
        await db.GetCollection<BsonDocument>("assets").InsertManyAsync([
            new BsonDocument { { "_id", ObjectId.Parse(AssetA) }, { "org_id", OrgId }, { "type", "domain" }, { "enabled", true }, { "domain", "a.com" } },
            new BsonDocument { { "_id", ObjectId.Parse(AssetC) }, { "org_id", OrgId }, { "type", "domain" }, { "enabled", true }, { "domain", "c.com" } },
        ]);
        await db.GetCollection<BsonDocument>("scans").InsertManyAsync([
            Scan("s1", now.AddHours(-3), AssetA, AssetC),
            Scan("s2", now.AddHours(-2), AssetC), // A disabled when s2 started
            Scan("s3", now.AddHours(-1), AssetA, AssetC),
        ]);
        await db.GetCollection<BsonDocument>("discoveries").InsertManyAsync([
            new BsonDocument { { "_id", "d-a" }, { "org_id", OrgId }, { "asset_type", "domain" }, { "domain", "a.com" }, { "asset_ids", new BsonArray { AssetA } } },
            new BsonDocument { { "_id", "d-c" }, { "org_id", OrgId }, { "asset_type", "domain" }, { "domain", "c.com" }, { "asset_ids", new BsonArray { AssetC } } },
        ]);
        await db.GetCollection<BsonDocument>("findings").InsertManyAsync([
            Finding("f-a", "d-a", "A still open", "open", "s1", "s3"),
            Finding("f-c-fixed", "d-c", "C fixed", "resolved", "s1"),
            Finding("f-c-new", "d-c", "C new", "open", "s3"),
        ]);
        return new TestServices(db, OrgId);
    }

    [Fact]
    public async Task SkippedFindings_AreNotChecked_NotResolved()
    {
        var services = await SeedAsync();

        var cmp = await services.ScansService().GetComparisonAsync("s1", "s2");

        Assert.NotNull(cmp);
        Assert.Equal(["C fixed"], cmp.Resolved.Select(f => f.Title).ToArray());
        Assert.Equal(1, cmp.NotCheckedCount);
    }

    [Fact]
    public async Task SkippedFindings_AreNotAdded_WhenTheAssetIsScannedAgain()
    {
        var services = await SeedAsync();

        var cmp = await services.ScansService().GetComparisonAsync("s2", "s3");

        Assert.NotNull(cmp);
        Assert.Equal(["C new"], cmp.Added.Select(f => f.Title).ToArray());
    }

    private static BsonDocument Scan(string id, DateTime at, params string[] targets) => new()
    {
        { "_id", id }, { "org_id", OrgId }, { "status", "done" }, { "type", "scheduled" },
        { "created_at", at }, { "updated_at", at }, { "started_at", at }, { "completed_at", at },
        { "targeted_assets", new BsonArray(targets.Select(t => new BsonDocument { { "asset_id", t }, { "type", "domain" }, { "value", t } })) },
    };

    private static BsonDocument Finding(string id, string discoveryId, string title, string status, params string[] scanIds) => new()
    {
        { "_id", id }, { "org_id", OrgId }, { "discovery_id", discoveryId }, { "scan_ids", new BsonArray(scanIds) },
        { "severity", "high" }, { "title", title }, { "finding_type", "type-" + id }, { "source", "nuclei" },
        { "status", status }, { "first_detected", DateTime.UtcNow }, { "last_detected", DateTime.UtcNow },
    };
}
