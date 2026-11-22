using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Driver;
using VulWall.Dashboard.Assets.Services;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Dashboard.Services;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.FindingSuppression;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Discoveries.Services;
using VulWall.Dashboard.Recommendations.Services;
using VulWall.Dashboard.Reports;
using VulWall.Dashboard.Reports.Services;
using VulWall.Dashboard.Reports.Services.ReportGeneration;
using VulWall.Dashboard.Scans.Services;

namespace VulWall.Dashboard.Tests.Infrastructure;

/// <summary>Builds the services under test against one test database and org, as DI would.</summary>
internal sealed class TestServices(IMongoDatabase db, string orgId)
{
    private readonly FixedOrganizationContext _org = new(orgId);

    public AssetsRepository Assets => new(db, _org, NullLogger<OrgScopedRepository<Asset, string>>.Instance);
    public DiscoveriesRepository Discoveries => new(db, _org, NullLogger<OrgScopedRepository<Discovery, string>>.Instance);
    public FindingsRepository Findings => new(db, _org, NullLogger<OrgScopedRepository<Finding, string>>.Instance);
    public ScansRepository Scans => new(db, _org, NullLogger<OrgScopedRepository<Scan, string>>.Instance);

    public IAssetScopeFilter AssetScope => new AssetScopeFilter(new AssetsPublicRepository(db), new DiscoveriesPublicRepository(db));

    public FindingSuppressionService Suppressions => new(
        new FindingSuppressionsRepository(db, _org, NullLogger<OrgScopedRepository<FindingSuppression, string>>.Instance));

    public KnowledgeBaseCacheService KnowledgeBase => new(db, new MemoryCache(new MemoryCacheOptions()));

    public DiscoveriesService DiscoveriesService() =>
        new(Discoveries, Findings, Scans, AssetScope, Suppressions, _org);

    public ScansService ScansService() => new(Scans, Findings, AssetScope, _org);

    public RecommendationsService RecommendationsService() =>
        new(Findings, Discoveries, Scans, KnowledgeBase, Suppressions, AssetScope, _org);

    public DashboardService DashboardService()
    {
        var kb = KnowledgeBase;
        return new DashboardService(Assets, Findings, Scans, Discoveries, kb,
            new SecurityScoreService(kb), Suppressions, AssetScope, _org);
    }

    public ReportsController ReportsController()
    {
        var kb = KnowledgeBase;
        var summary = new SummaryReportBuilder(new FindingsAggregator(), new VulnerabilitySummaryBuilder(), kb,
            new ScoreHistoryBuilder(), new FindingDeltaBuilder());
        return new ReportsController(NullLogger<ReportsController>.Instance, new OrganizationRepository(db), _org,
            summary, new TechnicalReportBuilder(summary, kb), Findings, Discoveries, Scans, new ReportsService(),
            Suppressions, AssetScope);
    }
}
