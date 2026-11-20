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
// - We find organizations by searching for Auth0 UserId in the user_ids array
// - The organization's _id becomes the org_id used to scope other entities
public class OrganizationRepository(IMongoDatabase database)
    : BaseMongoRepository<Entities.Organization.Organization, string>(database, "organizations");

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

// ScansPublicRepository uses BaseMongoRepository for anonymous access (e.g., webhooks)
public class ScansPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<Scan, string>(database, "scans")
{
    /// <summary>
    /// Partial update: sets only the executive_summary field on a scan document.
    /// </summary>
    public async Task UpdateExecutiveSummaryAsync(string scanId, string executiveSummary)
    {
        var filter = Builders<Scan>.Filter.Eq("_id", scanId);
        var update = Builders<Scan>.Update
            .Set("executive_summary", executiveSummary)
            .Set("updated_at", DateTime.UtcNow);
        await Database.GetCollection<Scan>("scans").UpdateOneAsync(filter, update);
    }
}

// FindingsPublicRepository uses BaseMongoRepository for anonymous access (e.g., webhooks)
public class FindingsPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<Finding, string>(database, "findings");

// DiscoveriesPublicRepository uses BaseMongoRepository for anonymous access (e.g., public certificates)
public class DiscoveriesPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<Discovery, string>(database, "discoveries");

// AuditLogPublicRepository uses BaseMongoRepository for anonymous access (e.g., Stripe webhooks)
public class AuditLogPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<AuditLog, string>(database, "audit_logs");

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

// DeletionLogRepository uses BaseMongoRepository (not OrgScoped) because:
// - Deletion logs outlive the organization — they must persist after the org is purged.
// - They contain no PII; only org_id + timestamp for compliance/audit.
public class DeletionLogRepository(IMongoDatabase database)
    : BaseMongoRepository<DeletionLog, string>(database, "deletion_logs");

public class FindingSuppressionsRepository(
    IMongoDatabase database,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<FindingSuppression, string>> logger)
    : OrgScopedRepository<FindingSuppression, string>(database, "finding_suppressions", orgContext, logger);

// FindingSuppressionsPublicRepository uses BaseMongoRepository for anonymous access (e.g., public certificate scoring)
public class FindingSuppressionsPublicRepository(IMongoDatabase database)
    : BaseMongoRepository<FindingSuppression, string>(database, "finding_suppressions");