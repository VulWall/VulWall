using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Services.AIServices;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Reports.Services.ExecutiveSummaryJob;
using VulWall.Dashboard.Reports.Services.ReportGeneration;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Reports;

[Collection(MongoCollection.Name)]
public class ExecutiveSummaryProcessorTests(MongoFixture mongo)
{
    private sealed class FakeAi(string? response) : IAIService
    {
        public int Calls { get; private set; }

        public Task<string?> GetResponseAsync(string promptName, string userMessage, string? model = null,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            return Task.FromResult(response);
        }
    }

    private sealed record Setup(IMongoDatabase Db, IMongoCollection<BsonDocument> Scans, FakeAi Ai)
    {
        public ExecutiveSummaryProcessor NewProcessor() => new(
            new ScansPublicRepository(Db),
            new FindingsPublicRepository(Db),
            new DiscoveriesPublicRepository(Db),
            new KnowledgeBaseCacheService(Db, new MemoryCache(new MemoryCacheOptions())),
            new ExecutiveSummaryService(Ai, NullLogger<ExecutiveSummaryService>.Instance),
            NullLogger<ExecutiveSummaryProcessor>.Instance);
    }

    private Setup Create(string? aiResponse = "Your perimeter looks healthy.")
    {
        var db = mongo.NewDatabase();
        return new Setup(db, db.GetCollection<BsonDocument>("scans"), new FakeAi(aiResponse));
    }

    [Fact]
    public async Task ProcessPending_WithAi_WritesSummaryAndMarksDone()
    {
        var s = Create();
        var id = await InsertScan(s, "done");

        var processed = await s.NewProcessor().ProcessPendingAsync(aiEnabled: true, CancellationToken.None);

        Assert.Equal(1, processed);
        var doc = await Get(s, id);
        Assert.Equal("done", doc["executive_summary_status"].AsString);
        Assert.Equal("Your perimeter looks healthy.", doc["executive_summary"].AsString);
        Assert.True(doc.Contains("started_at")); // scanner-owned field survives the partial update
    }

    [Fact]
    public async Task ProcessPending_WithoutAi_MarksSkippedAndCallsNoAi()
    {
        var s = Create();
        var id = await InsertScan(s, "done");

        await s.NewProcessor().ProcessPendingAsync(aiEnabled: false, CancellationToken.None);

        var doc = await Get(s, id);
        Assert.Equal("skipped", doc["executive_summary_status"].AsString);
        Assert.False(doc.Contains("executive_summary"));
        Assert.Equal(0, s.Ai.Calls);
    }

    [Fact]
    public async Task ProcessPending_EmptyAiResponse_MarksFailed()
    {
        var s = Create(aiResponse: null);
        var id = await InsertScan(s, "completed");

        await s.NewProcessor().ProcessPendingAsync(aiEnabled: true, CancellationToken.None);

        Assert.Equal("failed", (await Get(s, id))["executive_summary_status"].AsString);
    }

    [Fact]
    public async Task ProcessPending_ProcessesEachScanOnce()
    {
        var s = Create();
        await InsertScan(s, "done");
        var processor = s.NewProcessor();

        Assert.Equal(1, await processor.ProcessPendingAsync(true, CancellationToken.None));
        Assert.Equal(0, await processor.ProcessPendingAsync(true, CancellationToken.None));
        Assert.Equal(1, s.Ai.Calls);
    }

    [Fact]
    public async Task ProcessPending_ConcurrentWorkers_ClaimEachScanOnce()
    {
        var s = Create();
        for (var i = 0; i < 10; i++)
            await InsertScan(s, "done");

        var results = await Task.WhenAll(Enumerable.Range(0, 4)
            .Select(_ => s.NewProcessor().ProcessPendingAsync(true, CancellationToken.None)));

        Assert.Equal(10, results.Sum());
        Assert.Equal(10, s.Ai.Calls);
    }

    [Theory]
    [InlineData("queued")]
    [InlineData("running")]
    [InlineData("failed")]
    public async Task ProcessPending_IgnoresUnfinishedOrFailedScans(string status)
    {
        var s = Create();
        var id = await InsertScan(s, status);

        Assert.Equal(0, await s.NewProcessor().ProcessPendingAsync(true, CancellationToken.None));
        Assert.False((await Get(s, id)).Contains("executive_summary_status"));
    }

    [Fact]
    public async Task ProcessPending_IgnoresScansThatAlreadyHaveASummary()
    {
        var s = Create();
        await InsertScan(s, "done", extra: new BsonDocument("executive_summary", "From the old webhook"));

        Assert.Equal(0, await s.NewProcessor().ProcessPendingAsync(true, CancellationToken.None));
    }

    [Fact]
    public async Task ProcessPending_IgnoresScansCompletedLongAgo()
    {
        var s = Create();
        await InsertScan(s, "done", completedAt: DateTime.UtcNow.AddDays(-30));

        Assert.Equal(0, await s.NewProcessor().ProcessPendingAsync(true, CancellationToken.None));
    }

    [Fact]
    public async Task ProcessPending_ReclaimsStaleProcessingClaim()
    {
        var s = Create();
        var stale = await InsertScan(s, "done", extra: new BsonDocument
        {
            ["executive_summary_status"] = "processing",
            ["executive_summary_claimed_at"] = DateTime.UtcNow.AddHours(-1)
        });
        await InsertScan(s, "done", extra: new BsonDocument
        {
            ["executive_summary_status"] = "processing",
            ["executive_summary_claimed_at"] = DateTime.UtcNow
        });

        Assert.Equal(1, await s.NewProcessor().ProcessPendingAsync(true, CancellationToken.None));
        Assert.Equal("done", (await Get(s, stale))["executive_summary_status"].AsString);
    }

    private static async Task<string> InsertScan(Setup s, string status, DateTime? completedAt = null,
        BsonDocument? extra = null)
    {
        var id = Guid.NewGuid().ToString();
        var doc = new BsonDocument
        {
            ["_id"] = id,
            ["org_id"] = "org-1",
            ["status"] = status,
            ["type"] = "scheduled",
            ["created_at"] = DateTime.UtcNow.AddHours(-1),
            ["updated_at"] = DateTime.UtcNow,
            ["started_at"] = DateTime.UtcNow.AddHours(-1),
            ["completed_at"] = completedAt ?? DateTime.UtcNow
        };
        if (extra != null)
            doc.Merge(extra, overwriteExistingElements: true);
        await s.Scans.InsertOneAsync(doc);
        return id;
    }

    private static Task<BsonDocument> Get(Setup s, string id) =>
        s.Scans.Find(new BsonDocument("_id", id)).FirstAsync();
}
