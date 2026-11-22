using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Scans;

/// <summary>
/// Asset B is added after s1, so s2 is the first scan that targets it. The findings s2 found
/// on B are new, so the s1 to s2 comparison shows them as added. Asset A is in both scans.
/// </summary>
[Collection(MongoCollection.Name)]
public class NewAssetComparisonTests(MongoFixture mongo)
{
    private const string OrgId = "org-1";
    private static readonly string AssetA = ObjectId.GenerateNewId().ToString();
    private static readonly string AssetB = ObjectId.GenerateNewId().ToString();
    private static readonly DateTime S1At = DateTime.UtcNow.AddHours(-3);
    private static readonly DateTime S2At = DateTime.UtcNow.AddHours(-2);

    private async Task<TestServices> SeedAsync(params BsonDocument[] findings)
    {
        var db = mongo.NewDatabase();
        await db.GetCollection<BsonDocument>("assets").InsertManyAsync([
            new BsonDocument { { "_id", ObjectId.Parse(AssetA) }, { "org_id", OrgId }, { "type", "domain" }, { "enabled", true }, { "domain", "a.com" } },
            new BsonDocument { { "_id", ObjectId.Parse(AssetB) }, { "org_id", OrgId }, { "type", "domain" }, { "enabled", true }, { "domain", "b.com" } },
        ]);
        await db.GetCollection<BsonDocument>("scans").InsertManyAsync([
            Scan("s1", S1At, AssetA),
            Scan("s2", S2At, AssetA, AssetB),
        ]);
        await db.GetCollection<BsonDocument>("discoveries").InsertManyAsync([
            new BsonDocument { { "_id", "d-a" }, { "org_id", OrgId }, { "asset_type", "domain" }, { "domain", "a.com" }, { "asset_ids", new BsonArray { AssetA } } },
            new BsonDocument { { "_id", "d-b" }, { "org_id", OrgId }, { "asset_type", "domain" }, { "domain", "b.com" }, { "asset_ids", new BsonArray { AssetB } } },
        ]);
        await db.GetCollection<BsonDocument>("findings").InsertManyAsync(findings);
        return new TestServices(db, OrgId);
    }

    [Fact]
    public async Task FindingsOfANewAsset_AreAdded()
    {
        var services = await SeedAsync(
            Finding("f-a", "d-a", "A open", "type-a", S1At, "s1", "s2"),
            Finding("f-b", "d-b", "B new", "type-b", S2At.AddMinutes(5), "s2"));

        var cmp = await services.ScansService().GetComparisonAsync("s1", "s2");

        Assert.NotNull(cmp);
        Assert.Equal(["B new"], cmp.Added.Select(f => f.Title).ToArray());
        Assert.False(cmp.NoChange);
    }

    // Comparison groups findings by type, severity and source, across assets. An older finding
    // of an asset the baseline skipped must not hide a new finding of the same group.
    [Fact]
    public async Task NewFinding_IsAdded_WhenAnOlderSkippedFindingHasTheSameGroup()
    {
        var services = await SeedAsync(
            Finding("f-b-old", "d-b", "B old", "type-x", S1At.AddHours(-1), "s2"),
            Finding("f-b-new", "d-b", "B new", "type-x", S2At.AddMinutes(5), "s2"));

        var cmp = await services.ScansService().GetComparisonAsync("s1", "s2");

        Assert.NotNull(cmp);
        Assert.Equal(["B new"], cmp.Added.Select(f => f.Title).ToArray());
    }

    private static BsonDocument Scan(string id, DateTime at, params string[] targets) => new()
    {
        { "_id", id }, { "org_id", OrgId }, { "status", "done" }, { "type", "scheduled" },
        { "created_at", at }, { "updated_at", at }, { "started_at", at }, { "completed_at", at },
        { "targeted_assets", new BsonArray(targets.Select(t => new BsonDocument { { "asset_id", t }, { "type", "domain" }, { "value", t } })) },
    };

    private static BsonDocument Finding(string id, string discoveryId, string title, string type, DateTime firstDetected,
        params string[] scanIds) => new()
    {
        { "_id", id }, { "org_id", OrgId }, { "discovery_id", discoveryId }, { "scan_ids", new BsonArray(scanIds) },
        { "severity", "high" }, { "title", title }, { "finding_type", type }, { "source", "nuclei" },
        { "status", "open" }, { "first_detected", firstDetected }, { "last_detected", firstDetected },
    };
}
