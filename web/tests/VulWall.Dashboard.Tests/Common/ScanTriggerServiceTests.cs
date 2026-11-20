using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Common;

[Collection(MongoCollection.Name)]
public class ScanTriggerServiceTests(MongoFixture mongo)
{
    private const string OrgId = "org-1";

    private (ScanTriggerService Service, IMongoCollection<BsonDocument> Scans) Create()
    {
        var db = mongo.NewDatabase();
        var repo = new ScansRepository(db, new FixedOrganizationContext(OrgId),
            NullLogger<OrgScopedRepository<Scan, string>>.Instance);
        return (new ScanTriggerService(repo), db.GetCollection<BsonDocument>("scans"));
    }

    [Fact]
    public async Task TriggerAsync_NoScanInProgress_InsertsQueuedScanForOrg()
    {
        var (service, scans) = Create();

        var result = await service.TriggerAsync("admin@example.com");

        Assert.Equal(TriggerScanResult.Started, result);
        var doc = Assert.Single(await scans.Find(FilterDefinition<BsonDocument>.Empty).ToListAsync());
        Assert.Equal("queued", doc["status"].AsString);
        Assert.Equal(OrgId, doc["org_id"].AsString);
        Assert.Equal("requested", doc["type"].AsString);
        Assert.Equal("admin@example.com", doc["triggered_by"].AsString);
        Assert.Equal(BsonType.String, doc["_id"].BsonType);
        Assert.True(doc.Contains("created_at"));
        Assert.False(doc.Contains("executive_summary"));
    }

    [Theory]
    [InlineData("queued")]
    [InlineData("pending")]
    [InlineData("running")]
    public async Task TriggerAsync_ScanInProgress_ReturnsAlreadyRunningAndInsertsNothing(string status)
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc(status, DateTime.UtcNow.AddMinutes(-5)));

        var result = await service.TriggerAsync("admin@example.com");

        Assert.Equal(TriggerScanResult.AlreadyRunning, result);
        Assert.Equal(1, await scans.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
    }

    [Fact]
    public async Task TriggerAsync_SecondCall_ReturnsAlreadyRunning()
    {
        var (service, _) = Create();

        await service.TriggerAsync("a");
        var second = await service.TriggerAsync("a");

        Assert.Equal(TriggerScanResult.AlreadyRunning, second);
    }

    [Theory]
    [InlineData("done")]
    [InlineData("completed")]
    [InlineData("failed")]
    public async Task TriggerAsync_OnlyFinishedScans_Starts(string status)
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc(status, DateTime.UtcNow.AddMinutes(-5)));

        Assert.Equal(TriggerScanResult.Started, await service.TriggerAsync("a"));
    }

    [Fact]
    public async Task TriggerAsync_OrphanedRunningScanOlderThan24h_DoesNotBlock()
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc("running", DateTime.UtcNow.AddHours(-25)));

        Assert.Equal(TriggerScanResult.Started, await service.TriggerAsync("a"));
    }

    [Fact]
    public async Task TriggerAsync_ScanInProgressForOtherOrg_DoesNotBlock()
    {
        var (service, scans) = Create();
        var other = ScanDoc("running", DateTime.UtcNow);
        other["org_id"] = "org-2";
        await scans.InsertOneAsync(other);

        Assert.Equal(TriggerScanResult.Started, await service.TriggerAsync("a"));
    }

    private static BsonDocument ScanDoc(string status, DateTime createdAt) => new()
    {
        ["_id"] = Guid.NewGuid().ToString(),
        ["org_id"] = OrgId,
        ["status"] = status,
        ["type"] = "scheduled",
        ["created_at"] = createdAt,
        ["updated_at"] = createdAt
    };
}
