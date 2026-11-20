using System.Linq.Expressions;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Abstractions;

namespace VulWall.Dashboard.Data.Base;

/// <summary>
/// Repository that automatically filters all queries by organization ID.
/// Use this for tenant-specific data (Assets, Discoveries, Users, AuditLogs).
/// For global/shared data (CVEs, threat intel), use BaseMongoRepository directly.
/// </summary>
public abstract class OrgScopedRepository<TEntity, TId>(
    IMongoDatabase database,
    string collectionName,
    IOrganizationContext orgContext,
    ILogger<OrgScopedRepository<TEntity, TId>> logger)
    : BaseMongoRepository<TEntity, TId>(database, collectionName)
    where TEntity : class, IEntity<TId>, IOrganizationEntity
{
    public override async Task<TEntity?> GetByIdAsync(TId id)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var entities = await base.FindAsync(e => e.Id.Equals(id) && e.OrgId == orgId);
        return entities.FirstOrDefault();
    }

    public override async Task<IEnumerable<TEntity>> GetAllAsync()
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        logger.LogDebug("Fetching all {EntityType} for org: {OrgId}", typeof(TEntity).Name, orgId);
        return await base.FindAsync(e => e.OrgId == orgId);
    }

    public override async Task<TEntity> CreateAsync(TEntity entity)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        entity.OrgId = orgId;
        logger.LogDebug("Creating {EntityType} for org: {OrgId}", typeof(TEntity).Name, orgId);
        return await base.CreateAsync(entity);
    }

    public override async Task<IEnumerable<TEntity>> CreateManyAsync(IEnumerable<TEntity> entities)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var entitiesList = entities.ToList();

        foreach (var entity in entitiesList)
        {
            entity.OrgId = orgId;
        }

        logger.LogDebug("Creating {Count} {EntityType} for org: {OrgId}",
            entitiesList.Count, typeof(TEntity).Name, orgId);

        return await base.CreateManyAsync(entitiesList);
    }

    public override async Task<TEntity> UpdateAsync(TEntity entity)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var entityId = GetEntityId(entity);

        // Verify ownership before update
        var existing = await base.GetByIdAsync(entityId);
        if (existing == null)
        {
            throw new InvalidOperationException($"{typeof(TEntity).Name} with ID {entityId} not found");
        }

        if (existing.OrgId != orgId)
        {
            logger.LogWarning(
                "Attempted to update {EntityType} {EntityId} from org {EntityOrg} by user from org {UserOrg}",
                typeof(TEntity).Name, entityId, existing.OrgId, orgId);
            throw new UnauthorizedAccessException($"Cannot update {typeof(TEntity).Name} from different organization");
        }

        entity.OrgId = orgId;
        logger.LogDebug("Updating {EntityType} {EntityId} for org: {OrgId}",
            typeof(TEntity).Name, entityId, orgId);

        return await base.UpdateAsync(entity);
    }

    public override async Task<bool> DeleteAsync(TId id)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();

        // Verify ownership before delete
        var existing = await base.GetByIdAsync(id);
        if (existing == null)
        {
            return false;
        }

        if (existing.OrgId != orgId)
        {
            logger.LogWarning(
                "Attempted to delete {EntityType} {EntityId} from org {EntityOrg} by user from org {UserOrg}",
                typeof(TEntity).Name, id, existing.OrgId, orgId);
            throw new UnauthorizedAccessException($"Cannot delete {typeof(TEntity).Name} from different organization");
        }

        logger.LogDebug("Deleting {EntityType} {EntityId} for org: {OrgId}",
            typeof(TEntity).Name, id, orgId);

        return await base.DeleteAsync(id);
    }

    public override async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var combinedPredicate = CombineWithOrgFilter(predicate, orgId);
        return await base.FindAsync(combinedPredicate);
    }

    public override async Task<IEnumerable<TEntity>> FindAsync(
        Expression<Func<TEntity, bool>> predicate,
        int limit,
        int skip)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var combinedPredicate = CombineWithOrgFilter(predicate, orgId);
        return await base.FindAsync(combinedPredicate, limit, skip);
    }

    public override async Task<IEnumerable<TEntity>> FindAsync(
        Expression<Func<TEntity, bool>> predicate,
        Expression<Func<TEntity, object>> orderByProperty,
        Common.Contracts.Enums.SortDirection sortDirection = Common.Contracts.Enums.SortDirection.Ascending,
        int limit = 0,
        int skip = 0)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var combinedPredicate = CombineWithOrgFilter(predicate, orgId);
        return await base.FindAsync(combinedPredicate, orderByProperty, sortDirection, limit, skip);
    }

    public override async Task<long> CountAsync(Expression<Func<TEntity, bool>> predicate)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var combinedPredicate = CombineWithOrgFilter(predicate, orgId);
        return await base.CountAsync(combinedPredicate);
    }

    public override async Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> predicate)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var combinedPredicate = CombineWithOrgFilter(predicate, orgId);
        return await base.ExistsAsync(combinedPredicate);
    }

    private Expression<Func<TEntity, bool>> CombineWithOrgFilter(
        Expression<Func<TEntity, bool>> userPredicate,
        string orgId)
    {
        var parameter = userPredicate.Parameters[0];
        var orgProperty = Expression.Property(parameter, nameof(IOrganizationEntity.OrgId));
        var orgValue = Expression.Constant(orgId);
        var orgEquals = Expression.Equal(orgProperty, orgValue);
        var orgLambda = Expression.Lambda<Func<TEntity, bool>>(orgEquals, parameter);

        var combined = Expression.AndAlso(userPredicate.Body, orgLambda.Body);
        return Expression.Lambda<Func<TEntity, bool>>(combined, parameter);
    }
}
