using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Discoveries.Services;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Discoveries;

[Collection(MongoCollection.Name)]
public class DiscoveriesScanInProgressTests(MongoFixture mongo)
{
    [Theory]
    [InlineData(null, false)]
    [InlineData("done", false)]
    [InlineData("queued", true)]
    [InlineData("running", true)]
    public async Task IndexViewModel_ScanInProgress_DisablesRescan(string? status, bool expected)
    {
        var db = mongo.NewDatabase();
        if (status is not null)
        {
            await db.GetCollection<BsonDocument>("scans").InsertOneAsync(new BsonDocument
            {
                { "_id", Guid.NewGuid().ToString() }, { "org_id", "org-1" }, { "status", status },
                { "type", "scheduled" }, { "triggered_by", "system" },
                { "created_at", DateTime.UtcNow }, { "updated_at", DateTime.UtcNow },
            });
        }
        var service = new TestServices(db, "org-1").DiscoveriesService();

        Assert.Equal(expected, (await service.GetIndexViewModelAsync()).ScanInProgress);
    }
}
