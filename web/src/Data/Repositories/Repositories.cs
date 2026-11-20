using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Base;
using VulWall.Dashboard.Data.Entities;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.FindingSuppression;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;
using VulWall.Dashboard.Data.Entities.SharedLink;
using VulWall.Dashboard.Data.Entities.Organization;

namespace VulWall.Dashboard.Data.Repositories;

// OrganizationRepository uses BaseMongoRepository (not OrgScoped) because:
// - Organizations ARE the organizational boundary - they don't belong to another org
// - The organization's _id becomes the org_id used to scope other entities
public class OrganizationRepository(IMongoDatabase database)
    : BaseMongoRepository<Entities.Organization.Organization, string>(database, "organizations");

// UsersRepository is global: local logins are not org-scoped (a self-hosted install has one admin).
public class UsersRepository(IMongoDatabase database)
    : BaseMongoRepository<Entities.User.User, string>(database, "users");

public class AuditLogRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<AuditLog, string>> logger)
    : OrgScopedRepository<AuditLog, string>(database, "audit_logs", orgContext, logger);

public class AssetsRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<Asset, string>> logger)
    : OrgScopedRepository<Asset, string>(database, "assets", orgContext, logger);

public class DiscoveriesRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<Discovery, string>> logger)
    : OrgScopedRepository<Discovery, string>(database, "discoveries", orgContext, logger);

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

// SharedLinksRepository uses OrgScopedRepository for authenticated operations
// For public access by token, use SharedLinksPublicRepository
public class SharedLinksRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<SharedLink, string>> logger)
    : OrgScopedRepository<SharedLink, string>(database, "shared_links", orgContext, logger);

// SharedLinksPublicRepository uses BaseMongoRepository for public (anonymous) access by token
public class SharedLinksPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<SharedLink, string>(database, "shared_links");

// ScansPublicRepository uses BaseMongoRepository for access outside a user request
// (shared reports, background jobs).
public class ScansPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<Scan, string>(database, "scans")
{
    private const string SummaryStatusField = "executive_summary_status";
    private const string SummaryClaimedAtField = "executive_summary_claimed_at";

    /// <summary>
    /// Atomically claims one finished scan whose AI executive summary has not been attempted,
    /// by setting <c>executive_summary_status</c> to "processing". A claim older than
    /// <paramref name="staleClaimAfter"/> is taken again (the previous worker died).
    /// Only scans completed after <paramref name="completedAfter"/> qualify, so a database
    /// with a long scan history does not trigger one AI call per old scan.
    /// Scans that already carry an executive_summary are never claimed.
    /// </summary>
    public Task<Scan?> ClaimNextForExecutiveSummaryAsync(DateTime completedAfter, TimeSpan staleClaimAfter)
    {
        var now = DateTime.UtcNow;
        var f = Builders<Scan>.Filter;
        var filter = f.And(
            f.In("status", new[] { "done", "completed" }),
            f.Gte("completed_at", completedAfter),
            f.Eq("executive_summary", BsonNull.Value),
            f.Or(
                f.Exists(SummaryStatusField, false),
                f.And(
                    f.Eq(SummaryStatusField, ExecutiveSummaryStatus.Processing),
                    f.Lt(SummaryClaimedAtField, now - staleClaimAfter))));

        var update = Builders<Scan>.Update
            .Set(SummaryStatusField, ExecutiveSummaryStatus.Processing)
            .Set(SummaryClaimedAtField, now);

        return FindOneAndUpdateAsync(filter, update, new FindOneAndUpdateOptions<Scan>
        {
            ReturnDocument = ReturnDocument.After
        });
    }

    /// <summary>
    /// Records the outcome of a claimed scan. Partial update so the scanner's own fields
    /// (started_at, last_activity_at, ...) that the Scan entity does not map are kept.
    /// </summary>
    public Task CompleteExecutiveSummaryAsync(string scanId, string status, string? executiveSummary = null)
    {
        var update = Builders<Scan>.Update
            .Set(SummaryStatusField, status)
            .Set("updated_at", DateTime.UtcNow);
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
    : BaseMongoRepository<Discovery, string>(database, "discoveries");

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

// FindingSuppressionsPublicRepository uses BaseMongoRepository for anonymous access (e.g., shared reports)
public class FindingSuppressionsPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<FindingSuppression, string>(database, "finding_suppressions");