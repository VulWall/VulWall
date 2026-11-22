using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Discoveries;
using VulWall.Dashboard.Discoveries.Services;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Discoveries;

[Collection(MongoCollection.Name)]
public class DiscoveryOwnershipStatusTests(MongoFixture mongo)
{
    [Fact]
    public async Task UpdateOwnershipStatus_KeepsScannerFieldsTheEntityDoesNotMap()
    {
        var db = mongo.NewDatabase();
        var discoveries = db.GetCollection<BsonDocument>("discoveries");
        await discoveries.InsertOneAsync(ScannerDiscovery("d-1", "org-1"));

        var updated = await Service(db, "org-1").UpdateOwnershipStatusAsync("d-1", OwnershipStatus.NotMine);

        Assert.True(updated);
        var stored = await discoveries.Find(new BsonDocument("_id", "d-1")).SingleAsync();
        Assert.Equal(new BsonString("notmine"), stored["ownership_status"]);
        Assert.Equal("nginx 1.25", stored["banner"].AsString);
        Assert.Equal(new BsonArray { "http" }, stored["previous_services"]);
        Assert.Equal(new BsonArray { "asset-1", "asset-2" }, stored["asset_ids"]);
    }

    [Fact]
    public async Task UpdateOwnershipStatus_SameStatusAgain_ReturnsTrue()
    {
        var db = mongo.NewDatabase();
        await db.GetCollection<BsonDocument>("discoveries").InsertOneAsync(ScannerDiscovery("d-1", "org-1"));

        Assert.True(await Service(db, "org-1").UpdateOwnershipStatusAsync("d-1", OwnershipStatus.Verified));
    }

    [Fact]
    public async Task UpdateOwnershipStatus_OtherOrgsDiscovery_ReturnsFalseAndLeavesItUnchanged()
    {
        var db = mongo.NewDatabase();
        var discoveries = db.GetCollection<BsonDocument>("discoveries");
        var original = ScannerDiscovery("d-2", "org-2");
        await discoveries.InsertOneAsync(original);

        var updated = await Service(db, "org-1").UpdateOwnershipStatusAsync("d-2", OwnershipStatus.NotMine);

        Assert.False(updated);
        Assert.Equal(original, await discoveries.Find(new BsonDocument("_id", "d-2")).SingleAsync());
    }

    [Fact]
    public async Task Controller_UndefinedStatus_ReturnsBadRequestAndLeavesDiscoveryUnchanged()
    {
        var db = mongo.NewDatabase();
        var discoveries = db.GetCollection<BsonDocument>("discoveries");
        var original = ScannerDiscovery("d-1", "org-1");
        await discoveries.InsertOneAsync(original);

        var result = await new DiscoveriesController(Service(db, "org-1"))
            .UpdateOwnershipStatus("d-1", (OwnershipStatus)99);

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(original, await discoveries.Find(new BsonDocument("_id", "d-1")).SingleAsync());
    }

    [Fact]
    public async Task Controller_InvalidModelState_ReturnsBadRequestAndLeavesDiscoveryUnchanged()
    {
        var db = mongo.NewDatabase();
        var discoveries = db.GetCollection<BsonDocument>("discoveries");
        var original = ScannerDiscovery("d-1", "org-1");
        original["ownership_status"] = "notmine";
        await discoveries.InsertOneAsync(original);
        var controller = new DiscoveriesController(Service(db, "org-1"));
        controller.ModelState.AddModelError("ownershipStatus", "The value 'bogus' is not valid.");

        var result = await controller.UpdateOwnershipStatus("d-1", default);

        Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(original, await discoveries.Find(new BsonDocument("_id", "d-1")).SingleAsync());
    }

    private static BsonDocument ScannerDiscovery(string id, string orgId) => new()
    {
        { "_id", id }, { "org_id", orgId }, { "asset_type", "port" }, { "source", "naabu" },
        { "status", "active" }, { "ownership_status", "verified" },
        { "port", 443 }, { "ip", "192.0.2.10" },
        { "banner", "nginx 1.25" }, { "previous_services", new BsonArray { "http" } },
        { "asset_ids", new BsonArray { "asset-1", "asset-2" } },
    };

    private static DiscoveriesService Service(IMongoDatabase db, string orgId) =>
        new TestServices(db, orgId).DiscoveriesService();
}
