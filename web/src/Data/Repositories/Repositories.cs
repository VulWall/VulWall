using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Entities.ScanCoverage;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.FindingSuppression;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;
using VulWall.Dashboard.Data.Entities.Organization;
using VulWall.Dashboard.Data.Entities.SystemInfo;

namespace VulWall.Dashboard.Data.Repositories;

// OrganizationRepository uses BaseMongoRepository (not OrgScoped) because:
// - Organizations ARE the organizational boundary - they don't belong to another org
// - The organization's _id becomes the org_id used to scope other entities
public class OrganizationRepository(IMongoDatabase database)
    : BaseMongoRepository<Entities.Organization.Organization, string>(database, "organizations");

// UsersRepository is global: local logins are not org-scoped (a self-hosted install has one admin).
public class UsersRepository(IMongoDatabase database)
    : BaseMongoRepository<Entities.User.User, string>(database, "users");

// SystemInfoRepository is global and read-only here: the scanner writes its versions to system_info.
public class SystemInfoRepository(IMongoDatabase database)
    : BaseMongoRepository<ScannerSystemInfo, string>(database, "system_info");

public class AssetsRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<Asset, string>> logger)
    : OrgScopedRepository<Asset, string>(database, "assets", orgContext, logger);

public class DiscoveriesRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<Discovery, string>> logger)
    : OrgScopedRepository<Discovery, string>(database, "discoveries", orgContext, logger)
{
    /// <summary>The ids of the org's discoveries that match <paramref name="filter"/>, nothing else.</summary>
    public virtual async Task<List<string>> FindIdsAsync(FilterDefinition<Discovery> filter) =>
        await Collection.Find(await InOrgAsync(filter)).Project(d => d.Id).ToListAsync();
}

public class ScansRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<Scan, string>> logger)
    : OrgScopedRepository<Scan, string>(database, "scans", orgContext, logger);

public class FindingsRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<Finding, string>> logger)
    : OrgScopedRepository<Finding, string>(database, "findings", orgContext, logger);

// ScansPublicRepository uses BaseMongoRepository for access outside a user request
// (background jobs).
public class ScansPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<Scan, string>(database, "scans")
{
    private const string SummaryStatusField = "executive_summary_status";
    private const string SummaryClaimedAtField = "executive_summary_claimed_at";
    private const string SummaryAttemptsField = "executive_summary_attempts";

    /// <summary>Claims of one scan (first try included) before a failure is final.</summary>
    public const int MaxExecutiveSummaryAttempts = 3;

    /// <summary>Wait after the first and the second failed attempt before the next claim.</summary>
    public static readonly TimeSpan[] ExecutiveSummaryRetryBackoff = [TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30)];

    /// <summary>
    /// Atomically claims one finished scan whose AI executive summary is due, by setting
    /// <c>executive_summary_status</c> to "processing" and counting the attempt. Due means:
    /// <list type="bullet">
    /// <item>never attempted;</item>
    /// <item>"processing" for longer than <paramref name="staleClaimAfter"/> (the worker died);</item>
    /// <item>"failed" with fewer than <see cref="MaxExecutiveSummaryAttempts"/> attempts, once the
    /// backoff since the last claim has passed;</item>
    /// <item>"skipped" (AI was off when the scan finished) while <paramref name="aiEnabled"/>.</item>
    /// </list>
    /// Only scans completed after <paramref name="completedAfter"/> qualify, so a database
    /// with a long scan history does not trigger one AI call per old scan.
    /// Scans that already carry an executive_summary are never claimed.
    /// </summary>
    public Task<Scan?> ClaimNextForExecutiveSummaryAsync(DateTime completedAfter, TimeSpan staleClaimAfter, bool aiEnabled = true)
    {
        var now = DateTime.UtcNow;
        var f = Builders<Scan>.Filter;

        var due = new List<FilterDefinition<Scan>>
        {
            f.Exists(SummaryStatusField, false),
            f.And(
                f.Eq(SummaryStatusField, ExecutiveSummaryStatus.Processing),
                f.Lt(SummaryClaimedAtField, now - staleClaimAfter)),
            // Failed before attempts were counted, or after the first attempt.
            f.And(
                f.Eq(SummaryStatusField, ExecutiveSummaryStatus.Failed),
                f.Or(f.Exists(SummaryAttemptsField, false), f.Lte(SummaryAttemptsField, 1)),
                f.Lt(SummaryClaimedAtField, now - ExecutiveSummaryRetryBackoff[0])),
            f.And(
                f.Eq(SummaryStatusField, ExecutiveSummaryStatus.Failed),
                f.Eq(SummaryAttemptsField, 2),
                f.Lt(SummaryClaimedAtField, now - ExecutiveSummaryRetryBackoff[1]))
        };
        if (aiEnabled)
            due.Add(f.Eq(SummaryStatusField, ExecutiveSummaryStatus.Skipped));

        var filter = f.And(
            f.In("status", new[] { "done", "completed" }),
            f.Gte("completed_at", completedAfter),
            f.Eq("executive_summary", BsonNull.Value),
            f.Or(due));

        var update = Builders<Scan>.Update
            .Set(SummaryStatusField, ExecutiveSummaryStatus.Processing)
            .Set(SummaryClaimedAtField, now)
            .Inc(SummaryAttemptsField, 1);

        return FindOneAndUpdateAsync(filter, update, new FindOneAndUpdateOptions<Scan>
        {
            ReturnDocument = ReturnDocument.After
        });
    }

    /// <summary>
    /// Records the outcome of a claimed scan. Partial update so the scanner's own fields
    /// (last_activity_at, ...) that the Scan entity does not map are kept.
    /// </summary>
    public Task CompleteExecutiveSummaryAsync(string scanId, string status, string? executiveSummary = null)
    {
        var update = Builders<Scan>.Update
            .Set(SummaryStatusField, status)
            .Set("updated_at", DateTime.UtcNow);
        // A skip is not a failed attempt: give the scan its full retry budget once AI is on.
        if (status == ExecutiveSummaryStatus.Skipped)
            update = update.Set(SummaryAttemptsField, 0);
        if (executiveSummary != null)
            update = update.Set("executive_summary", executiveSummary);

        return Database.GetCollection<Scan>("scans")
            .UpdateOneAsync(Builders<Scan>.Filter.Eq("_id", scanId), update);
    }
}

public static class ExecutiveSummaryStatus
{
    public const string Processing = "processing";
    public const string Done = "done";
    public const string Skipped = "skipped";
    public const string Failed = "failed";
}

// FindingsPublicRepository uses BaseMongoRepository for access outside a user request (e.g., background jobs)
public class FindingsPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<Finding, string>(database, "findings");

// DiscoveriesPublicRepository uses BaseMongoRepository for access outside a user request (e.g., background jobs)
public class DiscoveriesPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<Discovery, string>(database, "discoveries")
{
    /// <summary>
    /// Id and asset_ids of the org's discoveries, without the rest of the document: every one, or
    /// only <paramref name="ids"/> when given.
    /// </summary>
    public async Task<List<(string Id, IReadOnlyCollection<string>? AssetIds)>> GetOwnersAsync(
        string orgId, IReadOnlyCollection<string>? ids = null)
    {
        var filter = Builders<Discovery>.Filter.Eq(d => d.OrgId, orgId);
        if (ids != null)
            filter &= Builders<Discovery>.Filter.In(d => d.Id, ids);
        var docs = await Collection.Find(filter)
            .Project(d => new { d.Id, d.AssetIds })
            .ToListAsync();
        return docs.Select(d => (d.Id, (IReadOnlyCollection<string>?)d.AssetIds)).ToList();
    }
}

// AssetsPublicRepository uses BaseMongoRepository for access outside a user request (e.g., background jobs)
public class AssetsPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<Asset, string>(database, "assets")
{
    public Task<List<string>> GetEnabledIdsAsync(string orgId) =>
        Collection.Find(a => a.OrgId == orgId && a.Enabled).Project(a => a.Id).ToListAsync();
}

// KnowledgeBaseRepository uses BaseMongoRepository (not OrgScoped) because:
// - KB entries are shared across all organizations (one entry per finding_type)
// - Only ~84 entries total, loaded once and cached in-memory per request
// - GetAllAsync returns only published entries; unpublished entries are hidden from all consumers
public class KnowledgeBaseRepository(IMongoDatabase database)
    : BaseMongoRepository<KnowledgeBaseEntry, string>(database, "knowledge_base")
{
    public override async Task<IEnumerable<KnowledgeBaseEntry>> GetAllAsync()
    {
        return await FindAsync(kb => kb.Published);
    }
}

public class FindingSuppressionsRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<FindingSuppression, string>> logger)
    : OrgScopedRepository<FindingSuppression, string>(database, "finding_suppressions", orgContext, logger);

// The scanner writes scan_coverage; the web app only removes records (asset deletion).
public class ScanCoverageRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<ScanCoverage, string>> logger)
    : OrgScopedRepository<ScanCoverage, string>(database, "scan_coverage", orgContext, logger);
