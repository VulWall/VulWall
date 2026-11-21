using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Extensions.Configuration;
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

    [Fact]
    public async Task TriggerAsync_QueuedScanExists_ReturnsAlreadyQueuedAndInsertsNothing()
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc("queued", DateTime.UtcNow.AddMinutes(-5)));

        var result = await service.TriggerAsync("admin@example.com");

        Assert.Equal(TriggerScanResult.AlreadyQueued, result);
        Assert.Equal(1, await scans.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
    }

    [Theory]
    [InlineData("pending")]
    [InlineData("running")]
    public async Task TriggerAsync_ScanRunning_QueuesOneFollowUpScan(string status)
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc(status, DateTime.UtcNow.AddMinutes(-5)));

        var result = await service.TriggerAsync("admin@example.com");

        Assert.Equal(TriggerScanResult.QueuedAfterCurrent, result);
        var queued = Assert.Single(await scans.Find(Builders<BsonDocument>.Filter.Eq("status", "queued")).ToListAsync());
        Assert.Equal(OrgId, queued["org_id"].AsString);
        Assert.Equal("requested", queued["type"].AsString);
        Assert.Equal("admin@example.com", queued["triggered_by"].AsString);
    }

    [Fact]
    public async Task TriggerAsync_ScanRunningAndFollowUpQueued_InsertsNothing()
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc("running", DateTime.UtcNow.AddMinutes(-5)));
        await scans.InsertOneAsync(ScanDoc("queued", DateTime.UtcNow.AddMinutes(-1)));

        Assert.Equal(TriggerScanResult.AlreadyQueued, await service.TriggerAsync("a"));
        Assert.Equal(2, await scans.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
    }

    [Fact]
    public async Task TriggerAsync_ConcurrentRequestsWhileRunning_QueueExactlyOneScan()
    {
        var db = mongo.NewDatabase();
        await MongoDbIndexManager.EnsureIndexesAsync(db);
        var repo = new ScansRepository(db, new FixedOrganizationContext(OrgId),
            NullLogger<OrgScopedRepository<Scan, string>>.Instance);
        var scans = db.GetCollection<BsonDocument>("scans");
        await scans.InsertOneAsync(ScanDoc("running", DateTime.UtcNow.AddMinutes(-5)));

        // Separate service instances, as for separate HTTP requests.
        var results = await Task.WhenAll(Enumerable.Range(0, 20)
            .Select(_ => Task.Run(() => new ScanTriggerService(repo).TriggerAsync("a"))));

        Assert.Equal(1, await scans.CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("status", "queued")));
        Assert.Single(results, r => r == TriggerScanResult.QueuedAfterCurrent);
        Assert.All(results.Where(r => r != TriggerScanResult.QueuedAfterCurrent),
            r => Assert.Equal(TriggerScanResult.AlreadyQueued, r));
    }

    [Fact]
    public async Task UniqueQueuedIndex_AllowsOneQueuedScanPerOrgOnly()
    {
        var db = mongo.NewDatabase();
        await MongoDbIndexManager.EnsureIndexesAsync(db);
        var scans = db.GetCollection<BsonDocument>("scans");

        await scans.InsertOneAsync(ScanDoc("queued", DateTime.UtcNow));
        await Assert.ThrowsAsync<MongoWriteException>(() => scans.InsertOneAsync(ScanDoc("queued", DateTime.UtcNow)));
        // Other statuses and other orgs are not limited.
        await scans.InsertOneAsync(ScanDoc("running", DateTime.UtcNow));
        await scans.InsertOneAsync(ScanDoc("done", DateTime.UtcNow));
        var other = ScanDoc("queued", DateTime.UtcNow);
        other["org_id"] = "org-2";
        await scans.InsertOneAsync(other);
    }

    [Fact]
    public async Task EnsureIndexes_WithExistingDuplicateQueuedScans_DoesNotFail()
    {
        var db = mongo.NewDatabase();
        var scans = db.GetCollection<BsonDocument>("scans");
        await scans.InsertOneAsync(ScanDoc("queued", DateTime.UtcNow));
        await scans.InsertOneAsync(ScanDoc("queued", DateTime.UtcNow));

        await MongoDbIndexManager.EnsureIndexesAsync(db);
    }

    [Fact]
    public async Task TriggerAsync_SecondCall_ReturnsAlreadyQueued()
    {
        var (service, _) = Create();

        await service.TriggerAsync("a");
        var second = await service.TriggerAsync("a");

        Assert.Equal(TriggerScanResult.AlreadyQueued, second);
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
    public async Task TriggerAsync_OrphanedRunningScanOlderThan24h_StartsAsBefore()
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc("running", DateTime.UtcNow.AddHours(-25)));

        Assert.Equal(TriggerScanResult.Started, await service.TriggerAsync("a"));
        Assert.Equal(1, await scans.CountDocumentsAsync(Builders<BsonDocument>.Filter.Eq("status", "queued")));
    }

    [Fact]
    public async Task TriggerAsync_ScanQueuedLongAgoStartedRecently_CountsAsRunning()
    {
        var (service, scans) = Create();
        var doc = ScanDoc("running", DateTime.UtcNow.AddHours(-30));
        doc["started_at"] = DateTime.UtcNow.AddHours(-1);
        await scans.InsertOneAsync(doc);

        Assert.Equal(TriggerScanResult.QueuedAfterCurrent, await service.TriggerAsync("a"));
        Assert.True(await service.IsScanInProgressAsync());
    }

    [Fact]
    public async Task IsScanInProgress_StartedMoreThan24hAgo_IsStale()
    {
        var (service, scans) = Create();
        var doc = ScanDoc("running", DateTime.UtcNow.AddHours(-30));
        doc["started_at"] = DateTime.UtcNow.AddHours(-25);
        await scans.InsertOneAsync(doc);

        Assert.False(await service.IsScanInProgressAsync());
    }

    [Fact]
    public async Task IsScanInProgress_RecentRunningScanWithoutStartedAt_UsesCreatedAt()
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc("running", DateTime.UtcNow.AddHours(-1)));

        Assert.True(await service.IsScanInProgressAsync());
    }

    [Fact]
    public async Task TriggerAsync_QueuedScanOlderThan24h_StillBlocks()
    {
        var (service, scans) = Create();
        await scans.InsertOneAsync(ScanDoc("queued", DateTime.UtcNow.AddHours(-30)));

        Assert.Equal(TriggerScanResult.AlreadyQueued, await service.TriggerAsync("a"));
        Assert.Equal(1, await scans.CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
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
