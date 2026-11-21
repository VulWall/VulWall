using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Assets;
using VulWall.Dashboard.Assets.Models;
using VulWall.Dashboard.Assets.Services;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Assets;

[Collection(MongoCollection.Name)]
public class AssetsControllerTests(MongoFixture mongo)
{
    [Fact]
    public async Task Add_DoesNotStartAScan_AndOffersTheFirstScan()
    {
        var db = mongo.NewDatabase();
        var orgContext = new FixedOrganizationContext("org-1");
        var assets = new AssetsRepository(db, orgContext, NullLogger<OrgScopedRepository<Asset, string>>.Instance);
        var scans = new ScansRepository(db, orgContext, NullLogger<OrgScopedRepository<Scan, string>>.Instance);
        var controller = new AssetsController(new AssetsService(assets, scans, new ScanTriggerService(scans)))
        {
            TempData = new TempDataDictionary(new DefaultHttpContext(), new InMemoryTempDataProvider())
        };

        var result = await controller.Add(new AddAssetInput { AssetType = AssetType.Ip, IpAddress = "8.8.8.8" });

        Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(0, await db.GetCollection<BsonDocument>("scans").CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
        Assert.Equal("8.8.8.8", controller.TempData["AssetAdded"]);
        Assert.Equal(nameof(AssetAddedScanState.FirstScan), controller.TempData["AssetAddedScanState"]);
    }

    private sealed class InMemoryTempDataProvider : ITempDataProvider
    {
        private IDictionary<string, object> _values = new Dictionary<string, object>();
        public IDictionary<string, object> LoadTempData(HttpContext context) => _values;
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) => _values = values;
    }
}
