using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Recommendations.Constants;
using VulWall.Dashboard.Recommendations.Models;
using VulWall.Dashboard.Reports.Models;
using VulWall.Dashboard.Tests.Infrastructure;
using FindingEntity = VulWall.Dashboard.Data.Entities.Finding.Finding;

namespace VulWall.Dashboard.Tests.Assets;

/// <summary>
/// Disabling an asset hides the discoveries only it owns (asset_ids) and their findings in every
/// reader; re-enabling shows them again; the toggle writes nothing to discoveries, findings or
/// suppressions. Documents are seeded raw, the way the scanner writes them (asset_ids hold the
/// hex of assets._id, which is an ObjectId).
/// </summary>
[Collection(MongoCollection.Name)]
public class DisabledAssetHidesDataTests(MongoFixture mongo)
{
    private const string BaselineScan = "scan-0";
    private const string LatestScan = "scan-1";

    // Titles of the open high findings, one finding type each.
    private const string AIssue = "A issue";                 // a.com, owned by A
    private const string BSubIssue = "B subdomain issue";    // api.b.com, owned by B
    private const string SharedIpIssue = "Shared IP issue";  // IP under api.b.com, owned by B and A
    private const string BIpIssue = "B IP issue";            // IP under api.b.com, owned by B only
    private const string LegacyIssue = "Legacy issue";       // no asset_ids
    private const string EmptyIssue = "Empty issue";         // asset_ids: [] (an asset delete is pending)
    private const string GoneAssetIssue = "Gone asset issue"; // asset_ids of a deleted asset
    private const string OrphanIssue = "Orphan issue";       // discovery does not exist

    private static readonly string[] VisibleWhenBDisabled = [AIssue, SharedIpIssue, LegacyIssue];
    private static readonly string[] HiddenWhenBDisabled = [BSubIssue, BIpIssue, GoneAssetIssue, OrphanIssue, EmptyIssue];
    private static readonly string[] VisibleWhenAllEnabled = [AIssue, BSubIssue, SharedIpIssue, BIpIssue, LegacyIssue];

    private sealed record Seed(IMongoDatabase Db, string OrgId, string AssetA, string AssetB, TestServices Services)
    {
        public async Task SetEnabled(string assetId, bool enabled)
        {
            var (success, error) = await Services.AssetsService().UpdateAssetStatusAsync(assetId, enabled);
            Assert.True(success, error);
        }

        public string FindingId(string title) => $"f-{title.Replace(' ', '-')}";
    }

    private async Task<Seed> CreateAsync()
    {
        var db = mongo.NewDatabase();
        var orgId = ObjectId.GenerateNewId().ToString();
        var assetA = ObjectId.GenerateNewId();
        var assetB = ObjectId.GenerateNewId();
        var goneAsset = ObjectId.GenerateNewId().ToString();
        var now = DateTime.UtcNow;

        await db.GetCollection<BsonDocument>("organizations").InsertOneAsync(new BsonDocument
        {
            { "_id", ObjectId.Parse(orgId) }, { "company_name", "Test Org" },
        });
        await db.GetCollection<BsonDocument>("assets").InsertManyAsync([
            new BsonDocument { { "_id", assetA }, { "org_id", orgId }, { "type", "domain" }, { "enabled", true }, { "domain", "a.com" }, { "added_on", now } },
            new BsonDocument { { "_id", assetB }, { "org_id", orgId }, { "type", "domain" }, { "enabled", true }, { "domain", "b.com" }, { "added_on", now } },
        ]);
        await db.GetCollection<BsonDocument>("scans").InsertManyAsync([
            ScanDoc(BaselineScan, orgId, now.AddDays(-1)),
            ScanDoc(LatestScan, orgId, now.AddMinutes(-5)),
        ]);

        var a = assetA.ToString();
        var b = assetB.ToString();
        await db.GetCollection<BsonDocument>("discoveries").InsertManyAsync([
            Discovery("d-a", orgId, "domain", new BsonArray { a }, domain: "a.com"),
            Discovery("d-b", orgId, "domain", new BsonArray { b }, domain: "b.com"),
            Discovery("d-b-api", orgId, "subdomain", new BsonArray { b }, domain: "b.com", subdomain: "api.b.com", parentId: "d-b"),
            Discovery("ip-shared", orgId, "ip", new BsonArray { b, a }, ip: "192.0.2.1", parentId: "d-b-api"),
            Discovery("ip-b", orgId, "ip", new BsonArray { b }, ip: "192.0.2.2", parentId: "d-b-api"),
            Discovery("d-legacy", orgId, "subdomain", null, domain: "c.com", subdomain: "old.c.com"),
            Discovery("d-empty", orgId, "subdomain", new BsonArray(), domain: "c.com", subdomain: "empty.c.com"),
            Discovery("d-gone", orgId, "subdomain", new BsonArray { goneAsset }, domain: "g.com", subdomain: "x.g.com"),
        ]);

        var seed = new Seed(db, orgId, a, b, new TestServices(db, orgId));
        await db.GetCollection<BsonDocument>("findings").InsertManyAsync([
            FindingDoc(seed, AIssue, "d-a"),
            FindingDoc(seed, BSubIssue, "d-b-api"),
            FindingDoc(seed, SharedIpIssue, "ip-shared"),
            FindingDoc(seed, BIpIssue, "ip-b"),
            FindingDoc(seed, LegacyIssue, "d-legacy"),
            FindingDoc(seed, EmptyIssue, "d-empty"),
            FindingDoc(seed, GoneAssetIssue, "d-gone"),
            FindingDoc(seed, OrphanIssue, "d-missing"),
        ]);
        return seed;
    }

    [Fact]
    public async Task AssetScope_HidesOnlyDiscoveriesWithoutAnEnabledOwner()
    {
        var s = await CreateAsync();
        await s.SetEnabled(s.AssetB, false);

        var scope = await s.Services.AssetScope.GetAsync(s.OrgId);
        var discoveries = (await s.Services.Discoveries.GetAllAsync()).ToList();

        Assert.Equal(
            ["d-a", "d-legacy", "ip-shared"],
            scope.Filter(discoveries).Select(d => d.Id).Order().ToArray());
        Assert.True(scope.IsHidden("d-b-api"));
        Assert.True(scope.IsHidden("d-gone"));
        Assert.True(scope.IsHidden("d-empty"));    // [] = an asset delete is pending
        Assert.False(scope.IsHidden("d-legacy"));  // no asset_ids field = not recorded, visible
        Assert.False(scope.IsHidden("d-missing")); // unknown is not "hidden"
        Assert.Equal(VisibleWhenBDisabled.Order(), TitlesOf(scope.Filter(await s.Services.Findings.GetAllAsync())));
    }

    [Fact]
    public async Task Dashboard_DropsDisabledAssetFindingsFromCountsAndScore()
    {
        var s = await CreateAsync();
        var enabled = await s.Services.DashboardService().GetIndexViewModelAsync();

        await s.SetEnabled(s.AssetB, false);
        var disabled = await s.Services.DashboardService().GetIndexViewModelAsync();

        Assert.Equal(VisibleWhenAllEnabled.Length, enabled.HighIssues);
        Assert.Equal(VisibleWhenBDisabled.Length, disabled.HighIssues);
        Assert.True(disabled.SecurityScore > enabled.SecurityScore,
            $"score {disabled.SecurityScore} should rise above {enabled.SecurityScore} when findings are hidden");
        Assert.Equal("a.com", disabled.PrimaryDomain);
    }

    [Fact]
    public async Task Recommendations_HideDisabledAssetFindings_AndTheirDetailIsNotFound()
    {
        var s = await CreateAsync();
        await s.SetEnabled(s.AssetB, false);
        var service = s.Services.RecommendationsService();

        var index = await service.GetIndexViewModelAsync();

        Assert.Equal(VisibleWhenBDisabled.Order(), RecommendationTitles(index));
        Assert.Null(await service.GetDetailViewModelAsync(s.FindingId(BSubIssue)));
        Assert.Null(await service.GetDetailViewModelAsync(s.FindingId(OrphanIssue)));
        var shared = await service.GetDetailViewModelAsync(s.FindingId(SharedIpIssue));
        Assert.NotNull(shared);
        Assert.Equal(["ip-shared"], shared.AffectedAssets.Select(a => a.DiscoveryId!).ToArray());
    }

    [Fact]
    public async Task Recommendations_DismissedList_LeavesOutDisabledAssetSuppressions()
    {
        var s = await CreateAsync();
        var suppressions = s.Services.Suppressions;
        await suppressions.SuppressAsync("d-a", "other-type", SuppressionStatus.AcceptedRisk, "admin", null);
        await suppressions.SuppressAsync("d-b-api", "other-type", SuppressionStatus.AcceptedRisk, "admin", null);

        await s.SetEnabled(s.AssetB, false);
        var disabled = await s.Services.RecommendationsService().GetIndexViewModelAsync();
        await s.SetEnabled(s.AssetB, true);
        var enabled = await s.Services.RecommendationsService().GetIndexViewModelAsync();

        Assert.Equal(["d-a"], disabled.DismissedFindings.Select(d => d.DiscoveryId).ToArray());
        Assert.Equal(["d-a", "d-b-api"], enabled.DismissedFindings.Select(d => d.DiscoveryId).Order().ToArray());
    }

    [Fact]
    public async Task Reports_LeaveOutDisabledAssetFindings()
    {
        var s = await CreateAsync();
        await s.SetEnabled(s.AssetB, false);
        var controller = s.Services.ReportsController();

        var index = Assert.IsType<IndexViewModel>(Assert.IsType<ViewResult>(await controller.Index()).Model);
        var summary = Assert.IsType<SummaryReportViewModel>(Assert.IsType<ViewResult>(await controller.Summary(LatestScan)).Model);
        var technical = Assert.IsType<TechnicalReportViewModel>(Assert.IsType<ViewResult>(await controller.Technical(LatestScan)).Model);

        Assert.Equal(VisibleWhenBDisabled.Length, index.Scans.Single(x => x.Id == LatestScan).High);
        Assert.Equal(VisibleWhenBDisabled.Order(), summary.HighFindings.Select(f => f.Title).Order().ToArray());
        Assert.Equal(VisibleWhenBDisabled.Order(), technical.HighFindings.Select(f => f.Title).Order().ToArray());
    }

    [Fact]
    public async Task Scans_LeaveOutDisabledAssetFindings()
    {
        var s = await CreateAsync();
        await s.SetEnabled(s.AssetB, false);
        var service = s.Services.ScansService();

        var index = await service.GetIndexViewModelAsync();
        var live = await service.GetLiveScanStatusAsync();
        var comparison = await service.GetComparisonAsync(BaselineScan, LatestScan);

        Assert.Equal(VisibleWhenBDisabled.Length, index.HeatmapData.Single(h => h.ScanId == LatestScan).High);
        Assert.StartsWith($"{VisibleWhenBDisabled.Length} issues", live.RecentRuns[0].Meta);
        Assert.NotNull(comparison);
        Assert.Equal(VisibleWhenBDisabled.Length, comparison.LatestTotal);
    }

    [Fact]
    public async Task Discoveries_HideDisabledAssetRows_AndSharedIpBecomesARoot()
    {
        var s = await CreateAsync();
        await s.SetEnabled(s.AssetB, false);

        var model = await s.Services.DiscoveriesService().GetIndexViewModelAsync();

        Assert.Equal(
            ["192.0.2.1", "a.com", "old.c.com"],
            model.Discoveries.Select(d => d.Name).Order().ToArray());
        Assert.Equal(1, model.Discoveries.Single(d => d.Name == "192.0.2.1").HighIssues);
        Assert.Equal(3, model.TotalDiscoveries);
    }

    [Fact]
    public async Task Discoveries_AllEnabled_SharedIpStaysUnderItsSubdomain()
    {
        var s = await CreateAsync();

        var model = await s.Services.DiscoveriesService().GetIndexViewModelAsync();

        Assert.Equal(["a.com", "b.com", "old.c.com"], model.Discoveries.Select(d => d.Name).Order().ToArray());
        Assert.Equal(["api.b.com"], model.Discoveries.Single(d => d.Name == "b.com").Children.Select(c => c.Name).ToArray());
    }

    [Fact]
    public async Task ReEnable_RestoresEverything_AndTogglingWritesNoData()
    {
        var s = await CreateAsync();
        var before = await SnapshotAsync(s.Db);
        var recommendationsBefore = RecommendationTitles(await s.Services.RecommendationsService().GetIndexViewModelAsync());

        await s.SetEnabled(s.AssetB, false);
        await s.Services.DashboardService().GetIndexViewModelAsync();
        await s.Services.DiscoveriesService().GetIndexViewModelAsync();
        Assert.Equal(VisibleWhenBDisabled.Order(),
            RecommendationTitles(await s.Services.RecommendationsService().GetIndexViewModelAsync()));
        Assert.Equal(before, await SnapshotAsync(s.Db));

        await s.SetEnabled(s.AssetB, true);

        Assert.Equal(before, await SnapshotAsync(s.Db));
        Assert.Equal(VisibleWhenAllEnabled.Order(), recommendationsBefore);
        Assert.Equal(recommendationsBefore,
            RecommendationTitles(await s.Services.RecommendationsService().GetIndexViewModelAsync()));
        Assert.Equal(VisibleWhenAllEnabled.Length, (await s.Services.DashboardService().GetIndexViewModelAsync()).HighIssues);
    }

    [Fact]
    public async Task Discoveries_RowCountsOnlyOpenNotSuppressedFindings()
    {
        // #50: a resolved or a suppressed finding does not count on a Discoveries row.
        var s = await CreateAsync();
        await s.Db.GetCollection<BsonDocument>("findings").InsertManyAsync([
            FindingDoc(s, "A resolved", "d-a", status: "resolved"),
            FindingDoc(s, "A suppressed", "d-a"),
        ]);
        await s.Services.Suppressions.SuppressAsync("d-a", "type-A-suppressed", SuppressionStatus.FalsePositive, "admin", null);

        var model = await s.Services.DiscoveriesService().GetIndexViewModelAsync();

        Assert.Equal(1, model.Discoveries.Single(d => d.Name == "a.com").HighIssues);
    }

    [Fact]
    public async Task SuppressFinding_OnDisabledAssetDiscovery_RedirectsWithAnErrorAndWritesNothing()
    {
        var s = await CreateAsync();
        await s.SetEnabled(s.AssetB, false);
        var controller = s.Services.RecommendationsController();

        var result = await controller.SuppressFinding(new SuppressFindingInput
        {
            DiscoveryId = "d-b-api", FindingType = "type-B-subdomain-issue", Status = SuppressionStatus.FalsePositive,
        }, returnFindingId: s.FindingId(BSubIssue));

        // A plain form post: back to the page with a flash message, not the 404 page.
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Detail", redirect.ActionName);
        Assert.NotNull(controller.TempData["Error"]);
        Assert.Equal(0, await s.Db.GetCollection<BsonDocument>("finding_suppressions").CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
    }

    [Fact]
    public async Task UnsuppressFinding_OnDisabledAssetDiscovery_RedirectsWithAnErrorAndKeepsTheSuppression()
    {
        var s = await CreateAsync();
        Assert.True(await s.Services.Suppressions.SuppressAsync("d-b-api", "type-x", SuppressionStatus.AcceptedRisk, "admin", null));
        var suppressionId = (await s.Services.Suppressions.GetActiveSuppressionsAsync()).Single().Id;
        await s.SetEnabled(s.AssetB, false);

        var controller = s.Services.RecommendationsController();

        var result = await controller.UnsuppressFinding(new UnsuppressFindingInput { SuppressionId = suppressionId });

        Assert.Equal("Index", Assert.IsType<RedirectToActionResult>(result).ActionName);
        Assert.NotNull(controller.TempData["Error"]);
        Assert.Single(await s.Services.Suppressions.GetActiveSuppressionsAsync());
    }

    [Fact]
    public async Task UpdateOwnershipStatus_OnDisabledAssetDiscovery_IsNotFound()
    {
        var s = await CreateAsync();
        await s.SetEnabled(s.AssetB, false);
        var service = s.Services.DiscoveriesService();

        Assert.False(await service.UpdateOwnershipStatusAsync("d-b-api", OwnershipStatus.NotMine));
        Assert.True(await service.UpdateOwnershipStatusAsync("ip-shared", OwnershipStatus.NotMine));
    }

    private static string[] TitlesOf(IEnumerable<FindingEntity> findings) =>
        findings.Select(f => f.Title).Order().ToArray();

    private static string[] RecommendationTitles(RecommendationsIndexViewModel model) =>
        model.CriticalFindings.Concat(model.HighFindings).Concat(model.MediumFindings).Concat(model.LowFindings)
            .Select(g => g.Title).Order().ToArray();

    private static async Task<string> SnapshotAsync(IMongoDatabase db)
    {
        var parts = new List<string>();
        foreach (var name in new[] { "discoveries", "findings", "finding_suppressions" })
        {
            var docs = await db.GetCollection<BsonDocument>(name).Find(FilterDefinition<BsonDocument>.Empty)
                .Sort(Builders<BsonDocument>.Sort.Ascending("_id")).ToListAsync();
            parts.Add(name + ":" + new BsonArray(docs).ToJson());
        }
        return string.Join("\n", parts);
    }

    private static BsonDocument ScanDoc(string id, string orgId, DateTime createdAt) => new()
    {
        { "_id", id }, { "org_id", orgId }, { "status", "done" }, { "type", "scheduled" },
        { "triggered_by", "system" }, { "created_at", createdAt }, { "updated_at", createdAt },
        { "started_at", createdAt }, { "completed_at", createdAt },
    };

    private static BsonDocument Discovery(string id, string orgId, string type, BsonArray? assetIds,
        string? domain = null, string? subdomain = null, string? ip = null, string? parentId = null)
    {
        var doc = new BsonDocument
        {
            { "_id", id }, { "org_id", orgId }, { "asset_type", type }, { "source", "test" },
            { "status", "active" }, { "ownership_status", "verified" },
            { "discovered_at", DateTime.UtcNow }, { "first_seen", DateTime.UtcNow }, { "last_seen", DateTime.UtcNow },
            { "scan_ids", new BsonArray { BaselineScan, LatestScan } },
            { "parent_id", parentId is null ? BsonNull.Value : parentId },
        };
        if (assetIds is not null) doc["asset_ids"] = assetIds;
        if (domain is not null) doc["domain"] = domain;
        if (subdomain is not null) doc["subdomain"] = subdomain;
        if (ip is not null) doc["ip"] = ip;
        return doc;
    }

    private static BsonDocument FindingDoc(Seed s, string title, string discoveryId, string status = "open") => new()
    {
        { "_id", s.FindingId(title) }, { "org_id", s.OrgId }, { "discovery_id", discoveryId },
        { "scan_ids", new BsonArray { BaselineScan, LatestScan } }, { "severity", "high" },
        { "title", title }, { "description", "" }, { "finding_type", "type-" + title.Replace(' ', '-') },
        { "source", "nuclei" }, { "status", status },
        { "first_detected", DateTime.UtcNow.AddDays(-1) }, { "last_detected", DateTime.UtcNow },
    };
}
