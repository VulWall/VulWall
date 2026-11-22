using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Assets.Services;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.FindingSuppression;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Tests.Infrastructure;
using ScanCoverageRecord = VulWall.Dashboard.Data.Entities.ScanCoverage.ScanCoverage;

namespace VulWall.Dashboard.Tests.Assets;

/// <summary>
/// Deleting an asset removes the discoveries that only it owns (asset_ids) with their findings,
/// suppressions and scan coverage. Shared discoveries lose the id and keep their data. Documents
/// are seeded raw, the way the scanner writes them (asset_ids hold the hex of assets._id).
///
/// Asset X is deleted. Y is an enabled asset, Z a disabled one. x.com -> www.x.com -> three IPs:
/// ip-x (X only, with a port), ip-shared (X and Y, with a port) and ip-z (X and Z). y-api is Y's
/// host that DNS under X also reaches (X added to it). d-legacy has no asset_ids. Org 2 holds
/// discoveries with the same asset id string, and records that point at org 1's discovery ids.
///
/// Every test runs twice: with the default batch size, and with one discovery per batch.
/// </summary>
[Collection(MongoCollection.Name)]
public class AssetDeleteCascadeTests(MongoFixture mongo) : AssetDeleteCascadeTestsBase(mongo, 1000);

[Collection(MongoCollection.Name)]
public class AssetDeleteCascadeBatchOfOneTests(MongoFixture mongo) : AssetDeleteCascadeTestsBase(mongo, 1);

public abstract class AssetDeleteCascadeTestsBase(MongoFixture mongo, int batchSize)
{
    private const string OrgId = "org-1";
    private const string OtherOrgId = "org-2";

    private static readonly string[] OwnedByXOnly = ["d-x", "d-x-www", "ip-x", "port-x"];
    private static readonly string[] Survivors = ["d-legacy", "d-y", "ip-shared", "ip-z", "port-shared", "y-api"];

    private sealed record Seed(IMongoDatabase Db, TestServices Services, string X, string Y, string Z)
    {
        public IMongoCollection<BsonDocument> C(string name) => Db.GetCollection<BsonDocument>(name);
    }

    private async Task<Seed> CreateAsync()
    {
        var db = mongo.NewDatabase();
        var x = ObjectId.GenerateNewId();
        var y = ObjectId.GenerateNewId();
        var z = ObjectId.GenerateNewId();
        var (xs, ys, zs) = (x.ToString(), y.ToString(), z.ToString());
        var now = DateTime.UtcNow;

        await db.GetCollection<BsonDocument>("assets").InsertManyAsync([
            new BsonDocument { { "_id", x }, { "org_id", OrgId }, { "type", "domain" }, { "enabled", true }, { "domain", "x.com" }, { "added_on", now } },
            new BsonDocument { { "_id", y }, { "org_id", OrgId }, { "type", "domain" }, { "enabled", true }, { "domain", "y.com" }, { "added_on", now } },
            new BsonDocument { { "_id", z }, { "org_id", OrgId }, { "type", "domain" }, { "enabled", false }, { "domain", "z.com" }, { "added_on", now } },
        ]);

        await db.GetCollection<BsonDocument>("discoveries").InsertManyAsync([
            Discovery(OrgId, "d-x", "domain", [xs], domain: "x.com"),
            Discovery(OrgId, "d-x-www", "subdomain", [xs], domain: "x.com", subdomain: "www.x.com", parentId: "d-x"),
            Discovery(OrgId, "ip-x", "ip", [xs], ip: "192.0.2.1", parentId: "d-x-www"),
            Discovery(OrgId, "port-x", "port", [xs], ip: "192.0.2.1", port: 443, parentId: "ip-x"),
            Discovery(OrgId, "ip-shared", "ip", [xs, ys], ip: "192.0.2.2", parentId: "d-x-www"),
            Discovery(OrgId, "port-shared", "port", [xs, ys], ip: "192.0.2.2", port: 22, parentId: "ip-shared"),
            Discovery(OrgId, "ip-z", "ip", [xs, zs], ip: "192.0.2.3", parentId: "d-x-www"),
            Discovery(OrgId, "d-y", "domain", [ys], domain: "y.com"),
            Discovery(OrgId, "y-api", "subdomain", [ys, xs], domain: "y.com", subdomain: "api.y.com", parentId: "d-y"),
            Discovery(OrgId, "d-legacy", "subdomain", null, domain: "c.com", subdomain: "old.c.com", parentId: "d-x"),
            // Org 2 holds the same asset id string. Its findings, suppressions and coverage below
            // also point at org 1's discovery ids, to show those deletes are org-scoped too.
            Discovery(OtherOrgId, "o2-d-x", "domain", [xs], domain: "x.com"),
            Discovery(OtherOrgId, "o2-ip-x", "ip", [xs], ip: "192.0.2.1", parentId: "o2-d-x"),
        ]);

        var findings = new List<BsonDocument>();
        var suppressions = new List<BsonDocument>();
        var coverage = new List<BsonDocument>();
        foreach (var (org, id) in Survivors.Concat(OwnedByXOnly).Select(id => (OrgId, id))
                     .Concat([(OtherOrgId, "o2-d-x"), (OtherOrgId, "o2-ip-x"), (OtherOrgId, "d-x"), (OtherOrgId, "ip-x")]))
        {
            findings.Add(new BsonDocument
            {
                { "_id", $"{org}/f-{id}" }, { "org_id", org }, { "discovery_id", id },
                // y-api's finding is missing from s2, which lists it as unchecked.
                { "scan_ids", id == "y-api" ? new BsonArray { "s1" } : new BsonArray { "s1", "s2" } },
                { "severity", "high" }, { "title", $"Issue on {id}" }, { "finding_type", $"type-{id}" }, { "source", "nuclei" },
                { "status", "open" }, { "first_detected", now }, { "last_detected", now },
            });
            suppressions.Add(new BsonDocument
            {
                { "_id", $"{org}/s-{id}" }, { "org_id", org }, { "discovery_id", id }, { "finding_type", $"type-{id}" },
                { "status", "accepted_risk" }, { "suppressed_by", "admin" }, { "suppressed_at", now }, { "active", false },
            });
            coverage.Add(new BsonDocument
            {
                { "_id", ObjectId.GenerateNewId() }, { "org_id", org }, { "scan_id", "s2" }, { "source", "nuclei" },
                { "discovery_id", id }, { "status", "ok" },
            });
        }
        await db.GetCollection<BsonDocument>("findings").InsertManyAsync(findings);
        await db.GetCollection<BsonDocument>("finding_suppressions").InsertManyAsync(suppressions);
        await db.GetCollection<BsonDocument>("scan_coverage").InsertManyAsync(coverage);

        // s2 lists findings of X's discoveries as unchecked: after the delete those ids dangle.
        await db.GetCollection<BsonDocument>("scans").InsertManyAsync([
            Scan("s1", now.AddHours(-2), [xs, ys], []),
            Scan("s2", now.AddHours(-1), [xs, ys], [$"{OrgId}/f-ip-x", $"{OrgId}/f-d-x-www", $"{OrgId}/f-y-api"]),
        ]);
        await db.GetCollection<BsonDocument>("knowledge_base").InsertOneAsync(new BsonDocument
        {
            { "_id", "kb-1" }, { "finding_type", "type-ip-x" }, { "published", true },
        });

        return new Seed(db, new TestServices(db, OrgId), xs, ys, zs);
    }

    private AssetsService Service(Seed s) => s.Services.AssetsService(batchSize);

    private async Task DeleteX(Seed s)
    {
        var (success, error) = await Service(s).DeleteAssetAsync(s.X);
        Assert.True(success, error);
    }

    [Fact]
    public async Task Delete_RemovesTheDataOnlyTheAssetOwns()
    {
        var s = await CreateAsync();

        await DeleteX(s);

        Assert.Equal(Survivors, await IdsAsync(s.C("discoveries"), OrgId));
        Assert.Equal(Survivors.Select(id => $"{OrgId}/f-{id}"), await IdsAsync(s.C("findings"), OrgId));
        Assert.Equal(Survivors.Select(id => $"{OrgId}/s-{id}"), await IdsAsync(s.C("finding_suppressions"), OrgId));
        Assert.Equal(Survivors, await DiscoveryIdsAsync(s.C("scan_coverage"), OrgId));
        Assert.Equal(0, await s.C("assets").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(s.X))));
    }

    [Fact]
    public async Task Delete_SharedIpAndPort_LoseTheIdAndKeepTheirFindings()
    {
        var s = await CreateAsync();

        await DeleteX(s);

        Assert.Equal([s.Y], await AssetIdsAsync(s, "ip-shared"));
        Assert.Equal([s.Y], await AssetIdsAsync(s, "port-shared"));
        Assert.Equal(1, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("discovery_id", "ip-shared")));
        Assert.Equal(1, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("discovery_id", "port-shared")));
    }

    // Whoever controls DNS under X can make the scanner add X to Y's hosts. Deleting X must not
    // delete them: only discoveries left with no owner go.
    [Fact]
    public async Task Delete_DiscoveryOfAnotherExistingAsset_ThatAlsoHoldsTheId_Survives()
    {
        var s = await CreateAsync();

        await DeleteX(s);

        Assert.Equal([s.Y], await AssetIdsAsync(s, "y-api"));
        Assert.Equal("d-y", (await DocAsync(s, "y-api"))["parent_id"].AsString);
        Assert.Equal(1, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("discovery_id", "y-api")));
    }

    [Fact]
    public async Task Delete_DiscoverySharedWithADisabledAsset_SurvivesAndStaysHidden()
    {
        var s = await CreateAsync();

        await DeleteX(s);

        Assert.Equal([s.Z], await AssetIdsAsync(s, "ip-z"));
        var scope = await s.Services.AssetScope.GetAsync(OrgId);
        Assert.True(scope.IsHidden("ip-z"));
        Assert.False(scope.IsHidden("ip-shared"));
    }

    [Fact]
    public async Task Delete_DiscoveryWithoutAssetIds_IsNotTouched()
    {
        var s = await CreateAsync();
        var before = await DocAsync(s, "d-legacy");

        await DeleteX(s);

        // Its parent d-x is deleted, but a document without asset_ids is left exactly as it was.
        Assert.Equal(before, await DocAsync(s, "d-legacy"));
        Assert.Equal(1, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("discovery_id", "d-legacy")));
    }

    [Fact]
    public async Task Delete_OtherOrganization_IsNotTouched()
    {
        var s = await CreateAsync();
        var before = await SnapshotAsync(s.Db, OtherOrgId);

        await DeleteX(s);

        Assert.Equal(before, await SnapshotAsync(s.Db, OtherOrgId));
        Assert.Equal(["o2-d-x", "o2-ip-x"], await IdsAsync(s.C("discoveries"), OtherOrgId));
        Assert.Equal(4, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("org_id", OtherOrgId)));
    }

    [Fact]
    public async Task Delete_SurvivorWhoseParentIsDeleted_LosesTheParentAndIsShown()
    {
        var s = await CreateAsync();

        await DeleteX(s);

        Assert.False((await DocAsync(s, "ip-shared")).Contains("parent_id"));
        Assert.False((await DocAsync(s, "ip-z")).Contains("parent_id"));
        Assert.Equal("ip-shared", (await DocAsync(s, "port-shared"))["parent_id"].AsString);

        var model = await s.Services.DiscoveriesService().GetIndexViewModelAsync();
        var ip = Assert.Single(model.Discoveries, d => d.Id == "ip-shared");
        Assert.Equal(1, ip.HighIssues);
        Assert.Equal(1, ip.PortsCount);
        Assert.DoesNotContain(model.Discoveries, d => d.Id == "ip-z"); // hidden: Z is disabled
    }

    [Fact]
    public async Task DisableThenDelete_GivesTheSameResult()
    {
        var direct = await CreateAsync();
        await DeleteX(direct);

        var s = await CreateAsync();
        var (disabled, error) = await Service(s).UpdateAssetStatusAsync(s.X, false);
        Assert.True(disabled, error);
        await DeleteX(s);

        Assert.Equal(await IdsAsync(direct.C("discoveries"), OrgId), await IdsAsync(s.C("discoveries"), OrgId));
        Assert.Equal(await IdsAsync(direct.C("findings"), OrgId), await IdsAsync(s.C("findings"), OrgId));
        Assert.Equal(await IdsAsync(direct.C("finding_suppressions"), OrgId), await IdsAsync(s.C("finding_suppressions"), OrgId));
        Assert.Equal(await DiscoveryIdsAsync(direct.C("scan_coverage"), OrgId), await DiscoveryIdsAsync(s.C("scan_coverage"), OrgId));
        Assert.Equal([s.Y], await AssetIdsAsync(s, "ip-shared"));
    }

    [Fact]
    public async Task Delete_SecondCall_ChangesNothing()
    {
        var s = await CreateAsync();
        await DeleteX(s);
        var after = await SnapshotAsync(s.Db, OrgId);

        var (success, error) = await Service(s).DeleteAssetAsync(s.X);

        Assert.False(success);
        Assert.Null(error); // not found
        Assert.Equal(after, await SnapshotAsync(s.Db, OrgId));
    }

    // MongoDB has no transaction here. A run that stops at any write leaves the asset, so the user
    // deletes it again; that retry must end in the same state as a run that never stopped. The
    // real DeleteAssetAsync is stopped after 0, 1, 2, ... writes until a run gets through.
    [Fact]
    public async Task Delete_RetryAfterARunThatStoppedAtAnyWrite_Completes()
    {
        var clean = await CreateAsync();
        await DeleteX(clean);
        var expected = await SnapshotAsync(clean.Db, OrgId, clean);

        int stopAfter;
        for (stopAfter = 0; ; stopAfter++)
        {
            var s = await CreateAsync();
            var faults = new Faults { StopAfterWrites = stopAfter };
            try
            {
                await FaultyService(s, faults).DeleteAssetAsync(s.X);
                break; // every write done: no stop point left
            }
            catch (SimulatedCrash)
            {
            }
            Assert.Equal(1, await s.C("assets").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(s.X))));

            await DeleteX(s);

            Assert.True(expected == await SnapshotAsync(s.Db, OrgId, s), $"retry after {stopAfter} writes");
        }
        // disable, pull, 5 writes per batch, asset delete
        Assert.Equal(2 + 5 * (int)Math.Ceiling(OwnedByXOnly.Length / (double)batchSize) + 1, stopAfter);
    }

    // A scan that adds an owner back between the select and the deletes (the in-memory window in
    // the scanner) must not cost that discovery its findings and the user's suppressions.
    [Fact]
    public async Task Delete_OwnerAddedBackAfterTheSelect_KeepsTheDiscoveryAndItsRecords()
    {
        var s = await CreateAsync();
        var faults = new Faults
        {
            AfterFindIds = async call =>
            {
                if (call == 1) // the select of the empty discoveries
                    await s.C("discoveries").UpdateOneAsync(
                        Builders<BsonDocument>.Filter.Eq("_id", "ip-x"),
                        Builders<BsonDocument>.Update.AddToSet("asset_ids", s.Y));
            }
        };

        var (success, error) = await FaultyService(s, faults).DeleteAssetAsync(s.X);

        Assert.True(success, error);
        Assert.Equal([s.Y], await AssetIdsAsync(s, "ip-x"));
        var onIpX = Builders<BsonDocument>.Filter.Eq("discovery_id", "ip-x") & Builders<BsonDocument>.Filter.Eq("org_id", OrgId);
        Assert.Equal(1, await s.C("findings").CountDocumentsAsync(onIpX));
        Assert.Equal(1, await s.C("finding_suppressions").CountDocumentsAsync(onIpX));
        Assert.Equal(1, await s.C("scan_coverage").CountDocumentsAsync(onIpX));
        // The others still go.
        Assert.Equal(0, await s.C("discoveries").CountDocumentsAsync(Builders<BsonDocument>.Filter.In("_id", ["d-x", "d-x-www", "port-x"])));
    }

    // A scan that read the asset as enabled before the disable is seen by the second check: the
    // delete stops, removes nothing and sets enabled back to what it was. A later delete finishes it.
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Delete_ScanStartedBeforeTheDisable_StopsAndRestoresTheAssetState(bool enabled)
    {
        var s = await CreateAsync();
        var byId = Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(s.X));
        await s.C("assets").UpdateOneAsync(byId, Builders<BsonDocument>.Update.Set("enabled", enabled));
        var faults = new Faults
        {
            AfterWrite = async write =>
            {
                if (write == 1) // the disable
                    await s.C("scans").InsertOneAsync(new BsonDocument
                    {
                        { "_id", "s-race" }, { "org_id", OrgId }, { "status", "running" }, { "type", "scheduled" },
                        { "created_at", DateTime.UtcNow }, { "started_at", DateTime.UtcNow },
                    });
            }
        };

        var (success, error) = await FaultyService(s, faults).DeleteAssetAsync(s.X);

        Assert.False(success);
        Assert.Equal(AssetsService.ScanInProgressDeleteError, error);
        Assert.Equal(enabled, (await s.C("assets").Find(byId).SingleAsync())["enabled"].AsBoolean);
        Assert.Equal(OwnedByXOnly.Concat(Survivors).Order(), await IdsAsync(s.C("discoveries"), OrgId));
        Assert.Equal([s.X, s.Y], await AssetIdsAsync(s, "ip-shared"));
        Assert.Equal(OwnedByXOnly.Length + Survivors.Length, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("org_id", OrgId)));

        await s.C("scans").UpdateOneAsync(Builders<BsonDocument>.Filter.Eq("_id", "s-race"), Builders<BsonDocument>.Update.Set("status", "done"));
        await DeleteX(s);
        Assert.Equal(Survivors, await IdsAsync(s.C("discoveries"), OrgId));
    }

    [Fact]
    public async Task Delete_KeepsScansAndTheKnowledgeBase_AndScanPagesStillRender()
    {
        var s = await CreateAsync();
        var scansBefore = await SnapshotCollectionAsync(s.C("scans"), FilterDefinition<BsonDocument>.Empty);
        var kbBefore = await SnapshotCollectionAsync(s.C("knowledge_base"), FilterDefinition<BsonDocument>.Empty);

        await DeleteX(s);

        Assert.Equal(scansBefore, await SnapshotCollectionAsync(s.C("scans"), FilterDefinition<BsonDocument>.Empty));
        Assert.Equal(kbBefore, await SnapshotCollectionAsync(s.C("knowledge_base"), FilterDefinition<BsonDocument>.Empty));

        // s2 still lists the deleted findings in unchecked_finding_ids and X in targeted_assets.
        var scans = s.Services.ScansService();
        var index = await scans.GetIndexViewModelAsync();
        Assert.Equal(2, index.TotalScans);
        Assert.NotNull(index.InitialComparison);
        var cmp = await scans.GetComparisonAsync("s1", "s2");
        Assert.NotNull(cmp);
        Assert.Empty(cmp.Added);
        Assert.Empty(cmp.Resolved);
        Assert.Equal(1, cmp.NotCheckedCount); // y-api's finding; the deleted ones are skipped
    }

    private static BsonDocument Discovery(string orgId, string id, string type, string[]? assetIds,
        string? domain = null, string? subdomain = null, string? ip = null, int? port = null, string? parentId = null)
    {
        var doc = new BsonDocument
        {
            { "_id", id }, { "org_id", orgId }, { "asset_type", type }, { "source", "test" }, { "status", "active" },
            { "ownership_status", "verified" }, { "scan_ids", new BsonArray { "s1", "s2" } },
            { "first_seen", DateTime.UtcNow }, { "last_seen", DateTime.UtcNow }, { "discovered_at", DateTime.UtcNow },
        };
        if (assetIds != null) doc["asset_ids"] = new BsonArray(assetIds);
        if (domain != null) doc["domain"] = domain;
        if (subdomain != null) doc["subdomain"] = subdomain;
        if (ip != null) doc["ip"] = ip;
        if (port != null) { doc["port"] = port.Value; doc["protocol"] = "tcp"; }
        if (parentId != null) doc["parent_id"] = parentId;
        return doc;
    }

    private static BsonDocument Scan(string id, DateTime at, string[] targets, string[] uncheckedIds) => new()
    {
        { "_id", id }, { "org_id", OrgId }, { "status", "done" }, { "type", "scheduled" },
        { "created_at", at }, { "updated_at", at }, { "started_at", at }, { "completed_at", at },
        { "targeted_assets", new BsonArray(targets.Select(t => new BsonDocument { { "asset_id", t }, { "type", "domain" }, { "value", t } })) },
        { "unchecked_finding_ids", new BsonArray(uncheckedIds) },
    };

    private static async Task<BsonDocument> DocAsync(Seed s, string id) =>
        await s.C("discoveries").Find(new BsonDocument { { "_id", id }, { "org_id", OrgId } }).SingleAsync();

    private static async Task<string[]> AssetIdsAsync(Seed s, string id) =>
        (await DocAsync(s, id))["asset_ids"].AsBsonArray.Select(v => v.AsString).ToArray();

    private static async Task<string[]> IdsAsync(IMongoCollection<BsonDocument> c, string orgId) =>
        (await c.Find(Builders<BsonDocument>.Filter.Eq("org_id", orgId)).ToListAsync())
            .Select(d => d["_id"].ToString()!).Order().ToArray();

    private static async Task<string[]> DiscoveryIdsAsync(IMongoCollection<BsonDocument> c, string orgId) =>
        (await c.Find(Builders<BsonDocument>.Filter.Eq("org_id", orgId)).ToListAsync())
            .Select(d => d["discovery_id"].AsString).Order().ToArray();

    // Everything of one org. The asset ids are replaced by role, so two seeds compare equal.
    private static async Task<string> SnapshotAsync(IMongoDatabase db, string orgId, Seed? roles = null)
    {
        var parts = new List<string>();
        foreach (var name in new[] { "assets", "discoveries", "findings", "finding_suppressions", "scans" })
            parts.Add(name + ":" + await SnapshotCollectionAsync(db.GetCollection<BsonDocument>(name),
                Builders<BsonDocument>.Filter.Eq("org_id", orgId)));
        parts.Add("scan_coverage:" + string.Join(",", await DiscoveryIdsAsync(db.GetCollection<BsonDocument>("scan_coverage"), orgId)));
        var text = string.Join("\n", parts);
        return roles == null ? text : text.Replace(roles.X, "X").Replace(roles.Y, "Y").Replace(roles.Z, "Z");
    }

    private static async Task<string> SnapshotCollectionAsync(IMongoCollection<BsonDocument> c, FilterDefinition<BsonDocument> filter)
    {
        var docs = await c.Find(filter).Sort(Builders<BsonDocument>.Sort.Ascending("_id")).ToListAsync();
        foreach (var d in docs)
            foreach (var key in new[] { "first_seen", "last_seen", "discovered_at", "first_detected", "last_detected",
                         "suppressed_at", "created_at", "updated_at", "started_at", "completed_at", "added_on" })
                d.Remove(key);
        return new BsonArray(docs).ToJson();
    }

    private AssetsService FaultyService(Seed s, Faults faults)
    {
        var org = new FixedOrganizationContext(OrgId);
        var scans = s.Services.Scans;
        return new AssetsService(new FaultyAssets(s.Db, org, faults), scans, new ScanTriggerService(scans),
            new FaultyDiscoveries(s.Db, org, faults), new FaultyFindings(s.Db, org, faults),
            new FaultySuppressions(s.Db, org, faults), new FaultyCoverage(s.Db, org, faults))
        {
            DeleteBatchSize = batchSize
        };
    }

    private sealed class SimulatedCrash : Exception;

    /// <summary>Counts the writes of the delete; can stop it, or act between its steps.</summary>
    private sealed class Faults
    {
        public int? StopAfterWrites { get; init; }
        public Func<int, Task>? AfterWrite { get; init; }
        public Func<int, Task>? AfterFindIds { get; init; }
        private int _writes;
        private int _finds;

        public async Task<T> Write<T>(Func<Task<T>> write)
        {
            if (_writes == StopAfterWrites)
                throw new SimulatedCrash();
            var result = await write();
            _writes++;
            if (AfterWrite != null)
                await AfterWrite(_writes);
            return result;
        }

        public async Task<List<string>> FindIds(Func<Task<List<string>>> find)
        {
            var result = await find();
            _finds++;
            if (AfterFindIds != null)
                await AfterFindIds(_finds);
            return result;
        }
    }

    private sealed class FaultyAssets(IMongoDatabase db, IOrganizationContext org, Faults f)
        : AssetsRepository(db, org, NullLogger<OrgScopedRepository<Asset, string>>.Instance)
    {
        public override Task<long> UpdateOneAsync(FilterDefinition<Asset> filter, UpdateDefinition<Asset> update) =>
            f.Write(() => base.UpdateOneAsync(filter, update));
        public override Task<long> DeleteManyAsync(FilterDefinition<Asset> filter) => f.Write(() => base.DeleteManyAsync(filter));
    }

    private sealed class FaultyDiscoveries(IMongoDatabase db, IOrganizationContext org, Faults f)
        : DiscoveriesRepository(db, org, NullLogger<OrgScopedRepository<Discovery, string>>.Instance)
    {
        public override Task<long> UpdateManyAsync(FilterDefinition<Discovery> filter, UpdateDefinition<Discovery> update) =>
            f.Write(() => base.UpdateManyAsync(filter, update));
        public override Task<long> DeleteManyAsync(FilterDefinition<Discovery> filter) => f.Write(() => base.DeleteManyAsync(filter));
        public override Task<List<string>> FindIdsAsync(FilterDefinition<Discovery> filter) => f.FindIds(() => base.FindIdsAsync(filter));
    }

    private sealed class FaultyFindings(IMongoDatabase db, IOrganizationContext org, Faults f)
        : FindingsRepository(db, org, NullLogger<OrgScopedRepository<Finding, string>>.Instance)
    {
        public override Task<long> DeleteManyAsync(FilterDefinition<Finding> filter) => f.Write(() => base.DeleteManyAsync(filter));
    }

    private sealed class FaultySuppressions(IMongoDatabase db, IOrganizationContext org, Faults f)
        : FindingSuppressionsRepository(db, org, NullLogger<OrgScopedRepository<FindingSuppression, string>>.Instance)
    {
        public override Task<long> DeleteManyAsync(FilterDefinition<FindingSuppression> filter) => f.Write(() => base.DeleteManyAsync(filter));
    }

    private sealed class FaultyCoverage(IMongoDatabase db, IOrganizationContext org, Faults f)
        : ScanCoverageRepository(db, org, NullLogger<OrgScopedRepository<ScanCoverageRecord, string>>.Instance)
    {
        public override Task<long> DeleteManyAsync(FilterDefinition<ScanCoverageRecord> filter) => f.Write(() => base.DeleteManyAsync(filter));
    }
}
