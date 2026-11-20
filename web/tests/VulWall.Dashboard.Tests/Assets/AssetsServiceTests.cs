using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Assets.Services;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Assets;

[Collection(MongoCollection.Name)]
public class AssetsServiceTests(MongoFixture mongo)
{
    private (AssetsService Service, IMongoCollection<BsonDocument> Assets) Create()
    {
        var db = mongo.NewDatabase();
        var orgContext = new FixedOrganizationContext("org-1");
        var assets = new AssetsRepository(db, orgContext, NullLogger<OrgScopedRepository<Asset, string>>.Instance);
        var scans = new ScansRepository(db, orgContext, NullLogger<OrgScopedRepository<Scan, string>>.Instance);
        return (new AssetsService(assets, scans, new ScanTriggerService(scans)), db.GetCollection<BsonDocument>("assets"));
    }

    [Fact]
    public async Task CreateIpAsset_PublicIp_IsEnabledImmediately()
    {
        var (service, assets) = Create();

        var (asset, error) = await service.CreateIpAssetAsync(" 8.8.8.8 ");

        Assert.Null(error);
        Assert.True(asset!.Enabled);
        var doc = await assets.Find(FilterDefinition<BsonDocument>.Empty).SingleAsync();
        Assert.True(doc["enabled"].AsBoolean);
        Assert.Equal("8.8.8.8", doc["ip"].AsString);
        Assert.False(doc.Contains("dns_verified_at"));
    }

    [Theory]
    [InlineData("10.0.0.1")]
    [InlineData("127.0.0.1")]
    [InlineData("not-an-ip")]
    public async Task CreateIpAsset_PrivateOrInvalid_IsRejected(string ip)
    {
        var (service, assets) = Create();

        var (asset, error) = await service.CreateIpAssetAsync(ip);

        Assert.Null(asset);
        Assert.NotNull(error);
        Assert.Equal(0, await assets.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
    }

    [Fact]
    public async Task UpdateAssetStatus_LegacyUnverifiedDomain_CanBeEnabled()
    {
        var (service, assets) = Create();
        var id = ObjectId.GenerateNewId();
        await assets.InsertOneAsync(new BsonDocument
        {
            ["_id"] = id,
            ["org_id"] = "org-1",
            ["type"] = "domain",
            ["enabled"] = false,
            ["dns_verified_at"] = BsonNull.Value,
            ["domain"] = "example.com",
            ["added_on"] = DateTime.UtcNow
        });

        var (success, error) = await service.UpdateAssetStatusAsync(id.ToString(), enabled: true);

        Assert.True(success, error);
        Assert.True((await assets.Find(new BsonDocument("_id", id)).SingleAsync())["enabled"].AsBoolean);
    }

    [Fact]
    public async Task GetAssets_LatestScanDegradedAsset_ShowsNotice()
    {
        var (service, assets) = Create();
        var (dead, _) = await service.CreateIpAssetAsync("8.8.8.8");
        var (live, _) = await service.CreateIpAssetAsync("1.1.1.1");
        var scans = assets.Database.GetCollection<BsonDocument>("scans");
        BsonDocument Done(string id, DateTime createdAt, BsonArray degraded) => new()
        {
            { "_id", id }, { "org_id", "org-1" }, { "status", "done" }, { "type", "scheduled" },
            { "triggered_by", "system" }, { "created_at", createdAt }, { "updated_at", createdAt },
            { "degraded_assets", degraded },
        };
        // The older scan flags the live asset too; only the latest scan counts.
        await scans.InsertManyAsync(
        [
            Done("old", DateTime.UtcNow.AddDays(-1), new BsonArray
            {
                new BsonDocument { { "asset_id", live!.Id }, { "domain", "x" }, { "reason", "dns_failures" } },
            }),
            Done("new", DateTime.UtcNow, new BsonArray
            {
                new BsonDocument { { "asset_id", dead!.Id }, { "domain", "gone.example" }, { "reason", "root_nxdomain" } },
            }),
        ]);

        var model = await service.GetAssetsAsync();

        Assert.StartsWith("Domain does not resolve", model.Assets.Single(a => a.Id == dead.Id).ScanNotice);
        Assert.Null(model.Assets.Single(a => a.Id == live.Id).ScanNotice);
    }

    [Theory]
    [InlineData("dns_failures", "The last scan couldn't check everything")]
    [InlineData("subdomain_enumeration_failed", "The last scan couldn't check everything")]
    [InlineData("root_nxdomain", "Domain does not resolve")]
    public void ScanNotice_ByReason(string reason, string prefix)
    {
        var scan = new Scan { OrgId = "org-1", DegradedAssets = [new DegradedAsset { AssetId = "a1", Domain = "d", Reason = reason }] };

        Assert.StartsWith(prefix, AssetsService.ScanNotice("a1", scan));
        Assert.Null(AssetsService.ScanNotice("a2", scan));
        Assert.Null(AssetsService.ScanNotice("a1", null));
    }
}
