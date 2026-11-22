using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Tests.Infrastructure;

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
/// </summary>
[Collection(MongoCollection.Name)]
public class AssetDeleteCascadeTests(MongoFixture mongo)
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

    private static async Task DeleteX(Seed s)
    {
        var (success, error) = await s.Services.AssetsService().DeleteAssetAsync(s.X);
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
        var (disabled, error) = await s.Services.AssetsService().UpdateAssetStatusAsync(s.X, false);
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

        var (success, error) = await s.Services.AssetsService().DeleteAssetAsync(s.X);

        Assert.False(success);
        Assert.Null(error); // not found
        Assert.Equal(after, await SnapshotAsync(s.Db, OrgId));
    }

    public enum CrashPoint { AfterPull, AfterChildRecords, AfterParentUnset, BeforeAssetDelete }

    // MongoDB has no transaction here. A run that stopped at any step leaves the asset, so the
    // user deletes it again; that retry must end in the same state as a run that never stopped.
    [Theory]
    [InlineData(CrashPoint.AfterPull)]
    [InlineData(CrashPoint.AfterChildRecords)]
    [InlineData(CrashPoint.AfterParentUnset)]
    [InlineData(CrashPoint.BeforeAssetDelete)]
    public async Task Delete_RetryAfterAPartialRun_Completes(CrashPoint crash)
    {
        var clean = await CreateAsync();
        await DeleteX(clean);
        var expected = await SnapshotAsync(clean.Db, OrgId, clean);

        var s = await CreateAsync();
        await SimulatePartialRunAsync(s, crash);
        Assert.Equal(1, await s.C("assets").CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("_id", ObjectId.Parse(s.X))));

        await DeleteX(s);

        Assert.Equal(expected, await SnapshotAsync(s.Db, OrgId, s));
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

    // The steps of DeleteAssetAsync, done by hand up to the crash point.
    private static async Task SimulatePartialRunAsync(Seed s, CrashPoint crash)
    {
        var f = Builders<BsonDocument>.Filter;
        var discoveries = s.C("discoveries");
        var org = f.Eq("org_id", OrgId);
        await discoveries.UpdateManyAsync(org & f.AnyEq("asset_ids", s.X), Builders<BsonDocument>.Update.Pull("asset_ids", s.X));
        if (crash == CrashPoint.AfterPull)
            return;

        var empty = f.Size("asset_ids", 0);
        var orphans = (await discoveries.Find(org & empty).ToListAsync()).Select(d => d["_id"].AsString).ToList();
        Assert.Equal(OwnedByXOnly.Order(), orphans.Order());
        foreach (var name in new[] { "findings", "finding_suppressions", "scan_coverage" })
            await s.C(name).DeleteManyAsync(org & f.In("discovery_id", orphans));
        if (crash == CrashPoint.AfterChildRecords)
            return;

        await discoveries.UpdateManyAsync(org & f.In("parent_id", orphans) & f.SizeGt("asset_ids", 0),
            Builders<BsonDocument>.Update.Unset("parent_id"));
        if (crash == CrashPoint.AfterParentUnset)
            return;

        await discoveries.DeleteManyAsync(org & f.In("_id", orphans) & empty);
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
}
