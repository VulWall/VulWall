using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.ScanCoverage;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Data;

[Collection(MongoCollection.Name)]
public class OrgScopedRepositoryTests(MongoFixture mongo)
{
    [Fact]
    public async Task DeleteManyAsync_Predicate_DoesNotDeleteOtherOrgsDocuments()
    {
        var db = mongo.NewDatabase();
        var raw = await SeedDiscoveriesAsync(db);

        var deleted = await Discoveries(db, "org-1").DeleteManyAsync(d => d.Source == "naabu");

        Assert.Equal(1, deleted);
        Assert.Equal(["d-2"], await IdsAsync(raw));
    }

    [Fact]
    public async Task DeleteManyAsync_Filter_DoesNotDeleteOtherOrgsDocuments()
    {
        var db = mongo.NewDatabase();
        var raw = await SeedDiscoveriesAsync(db);

        var deleted = await Discoveries(db, "org-1")
            .DeleteManyAsync(Builders<Discovery>.Filter.AnyEq("asset_ids", "asset-1"));

        Assert.Equal(1, deleted);
        Assert.Equal(["d-2"], await IdsAsync(raw));
    }

    [Fact]
    public async Task UpdateOneAsync_DoesNotMatchOtherOrgsDocument()
    {
        var db = mongo.NewDatabase();
        var raw = await SeedDiscoveriesAsync(db);
        var before = await raw.Find(new BsonDocument("_id", "d-2")).SingleAsync();

        var matched = await Discoveries(db, "org-1").UpdateOneAsync(
            Builders<Discovery>.Filter.Eq(d => d.Id, "d-2"),
            Builders<Discovery>.Update.Set(d => d.Source, "changed"));

        Assert.Equal(0, matched);
        Assert.Equal(before, await raw.Find(new BsonDocument("_id", "d-2")).SingleAsync());
    }

    [Fact]
    public async Task UpdateManyAsync_PullsOnlyFromCurrentOrg()
    {
        var db = mongo.NewDatabase();
        var raw = await SeedDiscoveriesAsync(db);
        var before = await raw.Find(new BsonDocument("_id", "d-2")).SingleAsync();

        var matched = await Discoveries(db, "org-1").UpdateManyAsync(
            Builders<Discovery>.Filter.AnyEq("asset_ids", "asset-1"),
            Builders<Discovery>.Update.Pull("asset_ids", "asset-1"));

        Assert.Equal(1, matched);
        var own = await raw.Find(new BsonDocument("_id", "d-1")).SingleAsync();
        Assert.Equal(new BsonArray { "asset-9" }, own["asset_ids"]);
        Assert.Equal("nginx", own["banner"].AsString);
        Assert.Equal(before, await raw.Find(new BsonDocument("_id", "d-2")).SingleAsync());
    }

    [Fact]
    public async Task FindOneAndUpdateAsync_DoesNotMatchOtherOrgsDocument()
    {
        var db = mongo.NewDatabase();
        await SeedDiscoveriesAsync(db);

        var result = await Discoveries(db, "org-1").FindOneAndUpdateAsync(
            Builders<Discovery>.Filter.Eq(d => d.Id, "d-2"),
            Builders<Discovery>.Update.Set(d => d.Source, "changed"));

        Assert.Null(result);
    }

    [Fact]
    public async Task GetByFieldAsync_DoesNotReturnOtherOrgsDocument()
    {
        var db = mongo.NewDatabase();
        await SeedDiscoveriesAsync(db);

        Assert.Null(await Discoveries(db, "org-1").GetByFieldAsync("_id", "d-2"));
        Assert.NotNull(await Discoveries(db, "org-2").GetByFieldAsync("_id", "d-2"));
    }

    [Fact]
    public async Task CreateManyAsync_Session_StoresCurrentOrgId()
    {
        var db = mongo.NewDatabase();
        var raw = db.GetCollection<BsonDocument>("discoveries");
        var entity = new Discovery { Id = "d-3", OrgId = "org-2", Source = "naabu" };

        // Standalone mongod: a session without a transaction.
        using (var session = await db.Client.StartSessionAsync())
        {
            await Discoveries(db, "org-1").CreateManyAsync([entity], session);
        }

        var stored = await raw.Find(new BsonDocument("_id", "d-3")).SingleAsync();
        Assert.Equal("org-1", stored["org_id"].AsString);
    }

    [Fact]
    public async Task ScanCoverage_ReadsAndDeletesScannerRecordsOfCurrentOrgOnly()
    {
        var db = mongo.NewDatabase();
        var raw = db.GetCollection<BsonDocument>("scan_coverage");
        // The shape the scanner upserts: no _id in the update, so MongoDB assigns an ObjectId.
        BsonDocument Record(string orgId) => new()
        {
            { "scan_id", "scan-1" }, { "source", "nuclei" }, { "discovery_id", "d-1" },
            { "org_id", orgId }, { "status", "completed" }, { "target", "https://example.test" },
            { "reported", new BsonArray() }, { "created_at", DateTime.UtcNow }, { "updated_at", DateTime.UtcNow },
        };
        await raw.InsertManyAsync([Record("org-1"), Record("org-2")]);
        var repo = new ScanCoverageRepository(db, new FixedOrganizationContext("org-1"),
            NullLogger<OrgScopedRepository<ScanCoverage, string>>.Instance);

        var own = Assert.Single(await repo.FindAsync(c => c.DiscoveryId == "d-1"));
        Assert.True(ObjectId.TryParse(own.Id, out _));

        Assert.Equal(1, await repo.DeleteManyAsync(c => c.DiscoveryId == "d-1"));
        var left = await raw.Find(FilterDefinition<BsonDocument>.Empty).SingleAsync();
        Assert.Equal("org-2", left["org_id"].AsString);
    }

    private static DiscoveriesRepository Discoveries(IMongoDatabase db, string orgId) =>
        new(db, new FixedOrganizationContext(orgId), NullLogger<OrgScopedRepository<Discovery, string>>.Instance);

    private static async Task<IMongoCollection<BsonDocument>> SeedDiscoveriesAsync(IMongoDatabase db)
    {
        var raw = db.GetCollection<BsonDocument>("discoveries");
        await raw.InsertManyAsync([Discovery("d-1", "org-1"), Discovery("d-2", "org-2")]);
        return raw;
    }

    private static BsonDocument Discovery(string id, string orgId) => new()
    {
        { "_id", id }, { "org_id", orgId }, { "asset_type", "subdomain" }, { "source", "naabu" },
        { "status", "active" }, { "ownership_status", "verified" }, { "banner", "nginx" },
        { "asset_ids", new BsonArray { "asset-1", "asset-9" } },
    };

    private static async Task<List<string>> IdsAsync(IMongoCollection<BsonDocument> raw) =>
        (await raw.Find(FilterDefinition<BsonDocument>.Empty).ToListAsync())
        .Select(d => d["_id"].AsString).OrderBy(id => id).ToList();
}
