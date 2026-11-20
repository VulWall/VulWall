using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.About.Services;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.About;

[Collection(MongoCollection.Name)]
public class AboutServiceTests(MongoFixture mongo)
{
    private const string OrgId = "org-1";
    private static readonly DateTime Now = new(2026, 11, 20, 12, 0, 0, DateTimeKind.Utc);

    private (AboutService Service, IMongoDatabase Db) Create()
    {
        var db = mongo.NewDatabase();
        var org = new FixedOrganizationContext(OrgId);
        var service = new AboutService(
            new SystemInfoRepository(db),
            new AssetsRepository(db, org, NullLogger<OrgScopedRepository<Asset, string>>.Instance),
            new ScansRepository(db, org, NullLogger<OrgScopedRepository<Scan, string>>.Instance));
        return (service, db);
    }

    [Fact]
    public async Task Get_WithoutScannerDocument_ShowsUnknown()
    {
        var (service, _) = Create();

        var info = await service.GetAsync("v1.0.0", Now);

        Assert.Equal("v1.0.0", info.Versions.Single(v => v.Label == "VulWall web").Value);
        Assert.All(info.Versions.Where(v => v.Label != "VulWall web"), v => Assert.Equal("unknown", v.Value));
        Assert.Contains("VulWall scanner: unknown", info.CopyText);
        Assert.Contains("Assets: 0", info.CopyText);
        Assert.Contains("Last scan: none", info.CopyText);
        Assert.Contains("Generated: 2026-11-20 12:00 UTC", info.CopyText);
    }

    [Fact]
    public async Task Get_WithScannerDocument_ShowsItsVersions()
    {
        var (service, db) = Create();
        await db.GetCollection<BsonDocument>("system_info").InsertOneAsync(new BsonDocument
        {
            { "_id", "scanner" },
            { "version", "v1.0.0" },
            { "nuclei", "3.11.1" },
            { "nuclei_templates", "v10.5.2" },
            { "nuclei_templates_updated_at", new DateTime(2026, 11, 19, 2, 0, 0, DateTimeKind.Utc) },
            { "testssl", "v3.2.5" },
            { "retire", "" },
            { "dbip_country_date", "2026-11-01" },
            { "dbip_asn_date", "2026-11-01" },
            { "some_future_field", 1 },
        });

        var info = await service.GetAsync("v1.0.0", Now);
        string Row(string label) => info.Versions.Single(v => v.Label == label).Value;

        Assert.Equal("v1.0.0", Row("VulWall scanner"));
        Assert.Equal("3.11.1", Row("nuclei"));
        Assert.Equal("v10.5.2 (updated 2026-11-19)", Row("nuclei templates"));
        Assert.Equal("v3.2.5", Row("testssl.sh"));
        Assert.Equal("unknown", Row("retire.js"));
        Assert.Equal("2026-11-01", Row("DB-IP country database"));
    }

    [Fact]
    public async Task Get_DevBuildVersions_AreShownAsIs()
    {
        var (service, db) = Create();
        await db.GetCollection<BsonDocument>("system_info").InsertOneAsync(new BsonDocument
        {
            { "_id", "scanner" },
            { "version", "dev (abc1234)" },
        });

        var info = await service.GetAsync("dev (abc1234)", Now);

        Assert.Equal("dev (abc1234)", info.Versions.Single(v => v.Label == "VulWall web").Value);
        Assert.Equal("dev (abc1234)", info.Versions.Single(v => v.Label == "VulWall scanner").Value);
        Assert.Contains("VulWall web: dev (abc1234)\n", info.CopyText.ReplaceLineEndings("\n"));
        Assert.Contains("VulWall scanner: dev (abc1234)\n", info.CopyText.ReplaceLineEndings("\n"));
    }

    [Fact]
    public async Task Get_ScannerValues_AreOneLineAndBounded()
    {
        var (service, db) = Create();
        await db.GetCollection<BsonDocument>("system_info").InsertOneAsync(new BsonDocument
        {
            { "_id", "scanner" },
            { "version", "v1\nInjected: line" },
            { "nuclei", new string('x', 500) },
        });

        var info = await service.GetAsync("dev", Now);

        Assert.Equal("v1Injected: line", info.Versions.Single(v => v.Label == "VulWall scanner").Value);
        Assert.Equal(64, info.Versions.Single(v => v.Label == "nuclei").Value.Length);
        Assert.DoesNotContain("\nInjected", info.CopyText);
    }

    [Fact]
    public async Task CopyText_HasCountsAndScanStatus_ButNoDomainsIpsOrEmails()
    {
        var (service, db) = Create();
        await db.GetCollection<BsonDocument>("assets").InsertManyAsync(
        [
            new BsonDocument { { "org_id", OrgId }, { "type", "domain" }, { "domain", "secret-customer.example" } },
            new BsonDocument { { "org_id", OrgId }, { "type", "ip" }, { "ip", "203.0.113.77" } },
            new BsonDocument { { "org_id", "other-org" }, { "type", "domain" }, { "domain", "other.example" } },
        ]);
        await db.GetCollection<BsonDocument>("scans").InsertManyAsync(
        [
            new BsonDocument
            {
                { "_id", "old" }, { "org_id", OrgId }, { "status", "done" }, { "type", "scheduled" },
                { "triggered_by", "scheduler" }, { "created_at", Now.AddDays(-8) },
            },
            new BsonDocument
            {
                { "_id", "new" }, { "org_id", OrgId }, { "status", "done" }, { "type", "requested" },
                { "triggered_by", "admin@secret-customer.example" },
                { "created_at", Now.AddDays(-1) }, { "completed_at", Now.AddHours(-20) },
                { "completion_reason", "pipeline_quiescent" },
                { "targeted_assets", new BsonArray
                    {
                        new BsonDocument { { "asset_id", "a1" }, { "type", "domain" }, { "value", "secret-customer.example" } },
                        new BsonDocument { { "asset_id", "a2" }, { "type", "ip" }, { "value", "203.0.113.77" } },
                    }
                },
            },
        ]);

        var info = await service.GetAsync("v1.0.0", Now);

        Assert.Contains("Assets: 2", info.CopyText);
        Assert.Contains("Last scan: done (pipeline_quiescent), 2026-11-19 16:00 UTC", info.CopyText);
        Assert.DoesNotContain("secret-customer", info.CopyText);
        Assert.DoesNotContain("other.example", info.CopyText);
        Assert.DoesNotContain("203.0.113.77", info.CopyText);
        Assert.DoesNotContain("@", info.CopyText);
        Assert.DoesNotMatch(@"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", info.CopyText);
    }
}
