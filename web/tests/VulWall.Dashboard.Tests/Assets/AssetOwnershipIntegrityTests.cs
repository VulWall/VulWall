using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Assets.Services;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Recommendations.Constants;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Assets;

/// <summary>
/// Who owns a discovery stays right across add, toggle and delete:
/// <list type="bullet">
/// <item>An added asset is recorded at once on the discoveries earlier scans found for it, with
/// the scanner's ids, so another asset's disable or delete no longer hides or deletes them.</item>
/// <item>A started delete marks the asset deleting; it can then only be deleted again.</item>
/// <item>A delete also pulls the ids of assets that no longer exist.</item>
/// <item>A dismissal needs a discovery that exists.</item>
/// </list>
/// Discoveries are seeded raw, the way the scanner writes them. The root <c>vwtest.invalid</c>
/// (asset A) was scanned and found <c>api.vwtest.invalid</c>, which resolved to 8.8.8.8 before
/// and to 8.8.4.4 now. Each IP has a port. Org 2 has a port on 8.8.4.4 too.
/// </summary>
[Collection(MongoCollection.Name)]
public class AssetOwnershipIntegrityTests(MongoFixture mongo)
{
    private static readonly string Org = ObjectId.GenerateNewId().ToString();
    private const string OtherOrg = "org-2";
    private const string Root = "vwtest.invalid";
    private const string Api = "api.vwtest.invalid";
    private const string OldIp = "8.8.8.8";
    private const string NowIp = "8.8.4.4";

    private static readonly string DomId = DiscoveryIds.Domain(Org, Root);
    private static readonly string ApiId = DiscoveryIds.Subdomain(Org, Api);
    private static readonly string OldIpId = DiscoveryIds.Ip(Org, OldIp);
    private static readonly string NowIpId = DiscoveryIds.Ip(Org, NowIp);
    private const string OldPortId = "port-old";
    private const string NowPortId = "port-now";
    private const string OtherOrgPortId = "o2-port-now";

    private sealed record Seed(IMongoDatabase Db, TestServices Services, string A)
    {
        public IMongoCollection<BsonDocument> C(string name) => Db.GetCollection<BsonDocument>(name);
        public AssetsService Assets => Services.AssetsService();
    }

    private async Task<Seed> CreateAsync()
    {
        var db = mongo.NewDatabase();
        var a = ObjectId.GenerateNewId();
        var aId = a.ToString();
        var now = DateTime.UtcNow;
        await db.GetCollection<BsonDocument>("assets").InsertOneAsync(Asset(a, Org, Root));

        var api = Discovery(Org, ApiId, "subdomain", [aId], parentId: DomId);
        api["subdomain"] = Api;
        api["resolution_history"] = new BsonArray
        {
            new BsonDocument { { "ip", OldIp }, { "first_seen", now.AddDays(-9) }, { "last_seen", now.AddDays(-2) } },
            new BsonDocument { { "ip", NowIp }, { "first_seen", now.AddDays(-2) } }, // current: no last_seen
        };
        await db.GetCollection<BsonDocument>("discoveries").InsertManyAsync([
            Discovery(Org, DomId, "domain", [aId]),
            api,
            Discovery(Org, OldIpId, "ip", [aId], ip: OldIp, parentId: ApiId),
            Discovery(Org, NowIpId, "ip", [aId], ip: NowIp, parentId: ApiId),
            Discovery(Org, OldPortId, "port", [aId], ip: OldIp, port: 22, parentId: OldIpId),
            Discovery(Org, NowPortId, "port", [aId], ip: NowIp, port: 443, parentId: NowIpId),
            Discovery(OtherOrg, OtherOrgPortId, "port", ["other"], ip: NowIp, port: 443),
        ]);

        await db.GetCollection<BsonDocument>("findings").InsertManyAsync(
            new[] { DomId, ApiId, OldIpId, NowIpId, OldPortId, NowPortId }.Select(id => Finding(Org, id)));
        await db.GetCollection<BsonDocument>("scans").InsertOneAsync(new BsonDocument
        {
            { "_id", "s1" }, { "org_id", Org }, { "status", "done" }, { "type", "scheduled" },
            { "created_at", now.AddHours(-1) }, { "updated_at", now.AddHours(-1) }, { "started_at", now.AddHours(-1) },
            { "completed_at", now.AddHours(-1) },
        });
        return new Seed(db, new TestServices(db, Org), aId);
    }

    // ---- 2. Ownership recorded when an asset is added ----

    [Fact]
    public async Task AddSubdomainAsset_IsRecordedOnTheHostItsCurrentIpAndThatIpsPorts()
    {
        var s = await CreateAsync();

        var (b, error) = await s.Assets.CreateDomainAssetAsync(Api);

        Assert.Null(error);
        Assert.Equal(Sorted(s.A, b!.Id), await OwnersAsync(s, ApiId));
        Assert.Equal(Sorted(s.A, b.Id), await OwnersAsync(s, NowIpId));
        Assert.Equal(Sorted(s.A, b.Id), await OwnersAsync(s, NowPortId));
        // Not the root, not an address the host no longer resolves to, not another org.
        Assert.Equal([s.A], await OwnersAsync(s, DomId));
        Assert.Equal([s.A], await OwnersAsync(s, OldIpId));
        Assert.Equal([s.A], await OwnersAsync(s, OldPortId));
        Assert.Equal(["other"], await OwnersAsync(s, OtherOrgPortId, OtherOrg));
    }

    // Audit T4: adding api after the root was scanned, then disabling or deleting the root.
    [Fact]
    public async Task AddSubdomainAsset_ThenDisableOrDeleteTheRoot_KeepsItsDataAndDismissals()
    {
        var s = await CreateAsync();
        await s.Assets.CreateDomainAssetAsync(Api);
        Assert.True(await s.Services.Suppressions.SuppressAsync(ApiId, $"type-{ApiId}", SuppressionStatus.AcceptedRisk, "admin", null));

        var (disabled, disableError) = await s.Assets.UpdateAssetStatusAsync(s.A, false);
        Assert.True(disabled, disableError);
        var scope = await s.Services.AssetScope.GetAsync(Org);
        Assert.True(scope.IsVisibleDiscovery(ApiId));
        Assert.True(scope.IsVisibleDiscovery(NowIpId));
        Assert.True(scope.IsVisibleDiscovery(NowPortId));
        Assert.True(scope.IsHidden(DomId));
        Assert.Contains((await s.Services.RecommendationsService().GetIndexViewModelAsync()).DismissedFindings,
            d => d.DiscoveryId == ApiId);

        var (deleted, deleteError) = await s.Assets.DeleteAssetAsync(s.A);

        Assert.True(deleted, deleteError);
        Assert.Equal(Sorted(ApiId, NowIpId, NowPortId), await IdsAsync(s.C("discoveries"), Org));
        Assert.Equal(Sorted(ApiId, NowIpId, NowPortId),
            (await s.C("findings").Find(Builders<BsonDocument>.Filter.Eq("org_id", Org)).ToListAsync())
            .Select(f => f["discovery_id"].AsString).Order().ToArray());
        Assert.Equal(1, await s.C("finding_suppressions").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("discovery_id", ApiId)));
    }

    // Deleting a domain and adding it again creates a new asset id; it is recorded like any add.
    [Fact]
    public async Task ReAddDeletedAsset_RecordsTheNewId()
    {
        var s = await CreateAsync();
        var (first, _) = await s.Assets.CreateDomainAssetAsync(Api);
        var (deleted, error) = await s.Assets.DeleteAssetAsync(first!.Id);
        Assert.True(deleted, error);
        Assert.Equal([s.A], await OwnersAsync(s, ApiId));

        var (again, _) = await s.Assets.CreateDomainAssetAsync(Api);

        Assert.NotEqual(first.Id, again!.Id);
        Assert.Equal(Sorted(s.A, again.Id), await OwnersAsync(s, ApiId));
        Assert.Equal(Sorted(s.A, again.Id), await OwnersAsync(s, NowPortId));
    }

    [Fact]
    public async Task AddIpAsset_IsRecordedOnTheIpAndItsPorts()
    {
        var s = await CreateAsync();

        var (ip, error) = await s.Assets.CreateIpAssetAsync($" {OldIp} ");

        Assert.Null(error);
        Assert.Equal(Sorted(s.A, ip!.Id), await OwnersAsync(s, OldIpId));
        Assert.Equal(Sorted(s.A, ip.Id), await OwnersAsync(s, OldPortId));
        Assert.Equal([s.A], await OwnersAsync(s, NowIpId));
        Assert.Equal([s.A], await OwnersAsync(s, ApiId));
    }

    [Fact]
    public async Task AddUnknownHost_CreatesNoDiscovery()
    {
        var s = await CreateAsync();
        var before = await SnapshotAsync(s.C("discoveries"));

        await s.Assets.CreateDomainAssetAsync("www.other-vwtest.invalid");
        await s.Assets.CreateIpAssetAsync("1.1.1.1");

        Assert.Equal(before, await SnapshotAsync(s.C("discoveries")));
    }

    // ---- 3. The deleting mark ----

    // Audit T5: a delete of A stopped after the pull; enabling A again must be refused, so the
    // org-wide sweep of empty discoveries in B's delete only removes data of an asset on its way out.
    [Fact]
    public async Task HalfDeletedAsset_CannotBeToggled_AndAnotherDeleteOnlySweepsItsData()
    {
        var s = await CreateAsync();
        var b = ObjectId.GenerateNewId();
        await s.C("assets").InsertOneAsync(Asset(b, Org, "b-vwtest.invalid"));
        await s.C("discoveries").InsertOneAsync(Discovery(Org, "d-b", "domain", [b.ToString()]));
        await s.C("findings").InsertOneAsync(Finding(Org, "d-b"));
        await HalfDeleteAsync(s, s.A);

        foreach (var enabled in new[] { true, false })
        {
            var (toggled, toggleError) = await s.Assets.UpdateAssetStatusAsync(s.A, enabled);
            Assert.False(toggled);
            Assert.Equal(AssetsService.DeletingToggleError, toggleError);
        }
        var a = await AssetDocAsync(s, s.A);
        Assert.False(a["enabled"].AsBoolean);
        Assert.True(a["deleting"].AsBoolean);
        var row = (await s.Assets.GetAssetsAsync()).Assets.Single(x => x.Id == s.A);
        Assert.True(row.Deleting);

        var (deletedB, errorB) = await s.Assets.DeleteAssetAsync(b.ToString());
        Assert.True(deletedB, errorB);
        Assert.Empty(await IdsAsync(s.C("discoveries"), Org));
        Assert.Equal(1, await s.C("assets").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("org_id", Org)));

        var (deletedA, errorA) = await s.Assets.DeleteAssetAsync(s.A);
        Assert.True(deletedA, errorA);
        Assert.Equal(0, await s.C("assets").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("org_id", Org)));
        Assert.Equal(0, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("org_id", Org)));
    }

    // A deleting asset counts as disabled everywhere, also if its enabled flag says otherwise.
    [Fact]
    public async Task DeletingAsset_IsNotAnEnabledOwner()
    {
        var s = await CreateAsync();
        await s.C("assets").UpdateOneAsync(AssetFilter(s.A), Builders<BsonDocument>.Update.Set("deleting", true));

        var scope = await s.Services.AssetScope.GetAsync(Org);

        Assert.True(scope.IsHidden(ApiId));
        Assert.True(scope.IsHidden(DomId));
    }

    // A full replace would drop fields the entity does not map, and would write back a stale
    // deleting flag; the toggle is a $set on enabled of a non-deleting asset of this org.
    [Fact]
    public async Task Toggle_IsAPartialOrgScopedUpdate()
    {
        var s = await CreateAsync();
        await s.C("assets").UpdateOneAsync(AssetFilter(s.A), Builders<BsonDocument>.Update.Set("written_elsewhere", "kept"));
        var other = ObjectId.GenerateNewId();
        await s.C("assets").InsertOneAsync(Asset(other, OtherOrg, Root));

        var (ok, error) = await s.Assets.UpdateAssetStatusAsync(s.A, false);
        var (otherOk, _) = await s.Assets.UpdateAssetStatusAsync(other.ToString(), false);

        Assert.True(ok, error);
        var a = await AssetDocAsync(s, s.A);
        Assert.False(a["enabled"].AsBoolean);
        Assert.Equal("kept", a["written_elsewhere"].AsString);
        Assert.False(a.Contains("deleting"));
        Assert.False(otherOk);
        Assert.True((await AssetDocAsync(s, other.ToString()))["enabled"].AsBoolean);
    }

    // A delete that marks the asset between the toggle's read and its write wins.
    [Fact]
    public async Task Toggle_RacingADelete_DoesNotClearTheMarkOrEnable()
    {
        var s = await CreateAsync();
        await s.C("assets").UpdateOneAsync(AssetFilter(s.A), Builders<BsonDocument>.Update.Set("enabled", false));
        var org = new FixedOrganizationContext(Org);
        var assets = new HookedAssets(s.Db, org)
        {
            BeforeUpdateOne = () => s.C("assets").UpdateOneAsync(AssetFilter(s.A),
                Builders<BsonDocument>.Update.Set("deleting", true))
        };
        var service = Service(s, assets, s.Services.Discoveries);

        var (ok, error) = await service.UpdateAssetStatusAsync(s.A, true);

        Assert.False(ok);
        Assert.Equal(AssetsService.DeletingToggleError, error);
        var a = await AssetDocAsync(s, s.A);
        Assert.False(a["enabled"].AsBoolean);
        Assert.True(a["deleting"].AsBoolean);
    }

    // The final step deletes only a marked asset: the mark is what kept its data consistent.
    [Fact]
    public async Task Delete_LastStep_RemovesOnlyAMarkedAsset()
    {
        var s = await CreateAsync();
        var org = new FixedOrganizationContext(Org);
        var discoveries = new HookedDiscoveries(s.Db, org)
        {
            AfterUpdateMany = () => s.C("assets").UpdateOneAsync(AssetFilter(s.A), Builders<BsonDocument>.Update.Unset("deleting"))
        };

        await Service(s, s.Services.Assets, discoveries).DeleteAssetAsync(s.A);

        Assert.Equal(1, await s.C("assets").CountDocumentsAsync(AssetFilter(s.A)));
    }

    [Fact]
    public async Task Delete_StoppedByAScan_LeavesNoMark()
    {
        var s = await CreateAsync();
        var org = new FixedOrganizationContext(Org);
        var first = true;
        var assets = new HookedAssets(s.Db, org)
        {
            AfterUpdateOne = async () =>
            {
                if (!first) return;
                first = false; // the disable
                await s.C("scans").InsertOneAsync(new BsonDocument
                {
                    { "_id", "s-race" }, { "org_id", Org }, { "status", "running" }, { "type", "scheduled" },
                    { "created_at", DateTime.UtcNow }, { "started_at", DateTime.UtcNow },
                });
            }
        };

        var (ok, error) = await Service(s, assets, s.Services.Discoveries).DeleteAssetAsync(s.A);

        Assert.False(ok);
        Assert.Equal(AssetsService.ScanInProgressDeleteError, error);
        var a = await AssetDocAsync(s, s.A);
        Assert.True(a["enabled"].AsBoolean);
        Assert.False(a.Contains("deleting"));
    }

    // ---- 1b. Ids of assets that no longer exist ----

    // A late scan message (before the scanner's guard, or through its cache window) left the id of
    // a deleted asset D. The next delete pulls it, and deletes what that leaves empty.
    [Fact]
    public async Task Delete_AlsoPullsIdsOfAssetsThatNoLongerExist()
    {
        var s = await CreateAsync();
        var dead = ObjectId.GenerateNewId().ToString();
        var y = ObjectId.GenerateNewId();
        await s.C("assets").InsertOneAsync(Asset(y, Org, "y-vwtest.invalid"));
        var x = (await s.Assets.CreateIpAssetAsync("9.9.9.9")).Asset!.Id;
        await s.C("discoveries").InsertManyAsync([
            Discovery(Org, "x-only", "ip", [x], ip: "9.9.9.9"),
            Discovery(Org, "dead-only", "subdomain", [dead]),
            Discovery(Org, "dead-and-y", "subdomain", [dead, y.ToString()]),
            Discovery(Org, "legacy", "subdomain", null),
            Discovery(OtherOrg, "o2-dead-only", "subdomain", [dead]),
        ]);
        await s.C("findings").InsertManyAsync([Finding(Org, "dead-only"), Finding(Org, "dead-and-y")]);

        var (ok, error) = await s.Assets.DeleteAssetAsync(x);

        Assert.True(ok, error);
        var left = await IdsAsync(s.C("discoveries"), Org);
        Assert.DoesNotContain("x-only", left);
        Assert.DoesNotContain("dead-only", left);
        Assert.Equal([y.ToString()], await OwnersAsync(s, "dead-and-y"));
        Assert.False((await DocAsync(s, "legacy", Org)).Contains("asset_ids"));
        Assert.Equal([s.A], await OwnersAsync(s, ApiId));
        Assert.Equal([dead], await OwnersAsync(s, "o2-dead-only", OtherOrg));
        Assert.Equal(0, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("discovery_id", "dead-only")));
        Assert.Equal(1, await s.C("findings").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("discovery_id", "dead-and-y")));
    }

    // An asset added while a delete runs is inserted before its id reaches a discovery, so the
    // delete never takes it for one that no longer exists.
    [Fact]
    public async Task Delete_AssetAddedMeanwhile_KeepsItsId()
    {
        var s = await CreateAsync();
        var z = ObjectId.GenerateNewId();
        var org = new FixedOrganizationContext(Org);
        var discoveries = new HookedDiscoveries(s.Db, org)
        {
            AfterRecordedAssetIds = async () =>
            {
                await s.C("assets").InsertOneAsync(Asset(z, Org, Api));
                await s.C("discoveries").UpdateOneAsync(Builders<BsonDocument>.Filter.Eq("_id", ApiId),
                    Builders<BsonDocument>.Update.AddToSet("asset_ids", z.ToString()));
            }
        };

        var (ok, error) = await Service(s, s.Services.Assets, discoveries).DeleteAssetAsync(s.A);

        Assert.True(ok, error);
        Assert.Equal([z.ToString()], await OwnersAsync(s, ApiId));
    }

    // ---- 4. Dismissals need a discovery that exists ----

    [Fact]
    public async Task Suppress_UnknownDiscovery_IsRefused()
    {
        var s = await CreateAsync();

        Assert.False(await s.Services.Suppressions.SuppressAsync("no-such-discovery", "t", SuppressionStatus.AcceptedRisk, "admin", null));
        Assert.False(await s.Services.Suppressions.SuppressAsync(OtherOrgPortId, "t", SuppressionStatus.AcceptedRisk, "admin", null));
        Assert.True(await s.Services.Suppressions.SuppressAsync(ApiId, "t", SuppressionStatus.AcceptedRisk, "admin", null));
        Assert.Equal([ApiId], (await s.C("finding_suppressions").Find(FilterDefinition<BsonDocument>.Empty).ToListAsync())
            .Select(d => d["discovery_id"].AsString).ToArray());
    }

    // ---- helpers ----

    /// <summary>What a delete of the asset leaves when it stops right after its pull.</summary>
    private static async Task HalfDeleteAsync(Seed s, string assetId)
    {
        await s.C("assets").UpdateOneAsync(AssetFilter(assetId),
            Builders<BsonDocument>.Update.Set("enabled", false).Set("deleting", true));
        await s.C("discoveries").UpdateManyAsync(Builders<BsonDocument>.Filter.Eq("org_id", Org),
            Builders<BsonDocument>.Update.Pull("asset_ids", assetId));
    }

    private static AssetsService Service(Seed s, AssetsRepository assets, DiscoveriesRepository discoveries)
    {
        var scans = s.Services.Scans;
        return new AssetsService(assets, scans, new ScanTriggerService(scans), discoveries,
            s.Services.Findings, s.Services.SuppressionsRepository, s.Services.ScanCoverage);
    }

    private sealed class HookedAssets(IMongoDatabase db, IOrganizationContext org)
        : AssetsRepository(db, org, NullLogger<OrgScopedRepository<Asset, string>>.Instance)
    {
        public Func<Task>? BeforeUpdateOne { get; init; }
        public Func<Task>? AfterUpdateOne { get; init; }

        public override async Task<long> UpdateOneAsync(FilterDefinition<Asset> filter, UpdateDefinition<Asset> update)
        {
            if (BeforeUpdateOne != null) await BeforeUpdateOne();
            var matched = await base.UpdateOneAsync(filter, update);
            if (AfterUpdateOne != null) await AfterUpdateOne();
            return matched;
        }
    }

    private sealed class HookedDiscoveries(IMongoDatabase db, IOrganizationContext org)
        : DiscoveriesRepository(db, org, NullLogger<OrgScopedRepository<Discovery, string>>.Instance)
    {
        public Func<Task>? AfterRecordedAssetIds { get; init; }
        public Func<Task>? AfterUpdateMany { get; init; }

        public override async Task<List<string>> GetRecordedAssetIdsAsync()
        {
            var ids = await base.GetRecordedAssetIdsAsync();
            if (AfterRecordedAssetIds != null) await AfterRecordedAssetIds();
            return ids;
        }

        public override async Task<long> UpdateManyAsync(FilterDefinition<Discovery> filter, UpdateDefinition<Discovery> update)
        {
            var matched = await base.UpdateManyAsync(filter, update);
            if (AfterUpdateMany != null) await AfterUpdateMany();
            return matched;
        }
    }

    private static BsonDocument Asset(ObjectId id, string orgId, string domain) => new()
    {
        { "_id", id }, { "org_id", orgId }, { "type", "domain" }, { "enabled", true }, { "domain", domain },
        { "added_on", DateTime.UtcNow },
    };

    private static BsonDocument Discovery(string orgId, string id, string type, string[]? assetIds,
        string? ip = null, int? port = null, string? parentId = null)
    {
        var doc = new BsonDocument
        {
            { "_id", id }, { "org_id", orgId }, { "asset_type", type }, { "source", "test" }, { "status", "active" },
            { "ownership_status", "verified" }, { "scan_ids", new BsonArray { "s1" } },
            { "first_seen", DateTime.UtcNow }, { "last_seen", DateTime.UtcNow }, { "discovered_at", DateTime.UtcNow },
        };
        if (assetIds != null) doc["asset_ids"] = new BsonArray(assetIds);
        if (type == "domain") doc["domain"] = Root;
        if (ip != null) doc["ip"] = ip;
        if (port != null) { doc["port"] = port.Value; doc["protocol"] = "tcp"; }
        if (parentId != null) doc["parent_id"] = parentId;
        return doc;
    }

    private static BsonDocument Finding(string orgId, string discoveryId) => new()
    {
        { "_id", $"{orgId}/f-{discoveryId}" }, { "org_id", orgId }, { "discovery_id", discoveryId },
        { "scan_ids", new BsonArray { "s1" } }, { "severity", "high" }, { "title", $"Issue on {discoveryId}" },
        { "finding_type", $"type-{discoveryId}" }, { "source", "nuclei" }, { "status", "open" },
        { "first_detected", DateTime.UtcNow }, { "last_detected", DateTime.UtcNow },
    };

    private static FilterDefinition<BsonDocument> AssetFilter(string id) =>
        Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(id));

    private static Task<BsonDocument> AssetDocAsync(Seed s, string id) => s.C("assets").Find(AssetFilter(id)).SingleAsync();

    private static Task<BsonDocument> DocAsync(Seed s, string id, string orgId) =>
        s.C("discoveries").Find(new BsonDocument { { "_id", id }, { "org_id", orgId } }).SingleAsync();

    private static async Task<string[]> OwnersAsync(Seed s, string id, string? orgId = null) =>
        (await DocAsync(s, id, orgId ?? Org))["asset_ids"].AsBsonArray.Select(v => v.AsString).Order().ToArray();

    private static string[] Sorted(params string[] ids) => ids.Order().ToArray();

    private static async Task<string[]> IdsAsync(IMongoCollection<BsonDocument> c, string orgId) =>
        (await c.Find(Builders<BsonDocument>.Filter.Eq("org_id", orgId)).ToListAsync())
            .Select(d => d["_id"].ToString()!).Order().ToArray();

    private static async Task<string> SnapshotAsync(IMongoCollection<BsonDocument> c) =>
        new BsonArray(await c.Find(FilterDefinition<BsonDocument>.Empty).Sort(Builders<BsonDocument>.Sort.Ascending("_id")).ToListAsync()).ToJson();
}
