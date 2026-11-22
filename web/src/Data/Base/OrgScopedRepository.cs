using System.Linq.Expressions;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Abstractions;

namespace VulWall.Dashboard.Data.Base;

/// <summary>
/// Repository that automatically filters all queries by organization ID.
/// Use this for tenant-specific data (Assets, Discoveries, Users).
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
                typeof(TEntity).Name, LogSanitizer.Clean(entityId?.ToString()), existing.OrgId, orgId);
            throw new UnauthorizedAccessException($"Cannot update {typeof(TEntity).Name} from different organization");
        }

        entity.OrgId = orgId;
        logger.LogDebug("Updating {EntityType} {EntityId} for org: {OrgId}",
            typeof(TEntity).Name, LogSanitizer.Clean(entityId?.ToString()), orgId);

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
                typeof(TEntity).Name, LogSanitizer.Clean(id?.ToString()), existing.OrgId, orgId);
            throw new UnauthorizedAccessException($"Cannot delete {typeof(TEntity).Name} from different organization");
        }

        logger.LogDebug("Deleting {EntityType} {EntityId} for org: {OrgId}",
            typeof(TEntity).Name, LogSanitizer.Clean(id?.ToString()), orgId);

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

    public override async Task<TEntity?> GetByFieldAsync(string fieldName, object value)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var filter = Builders<TEntity>.Filter.Eq(fieldName, value) & OrgFilter(orgId);
        return await Collection.Find(filter).FirstOrDefaultAsync();
    }

    public override async Task CreateManyAsync(
        IEnumerable<TEntity> entities,
        IClientSessionHandle session,
        CancellationToken cancellationToken = default)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        var entitiesList = entities.ToList();
        foreach (var entity in entitiesList)
        {
            entity.OrgId = orgId;
        }

        await base.CreateManyAsync(entitiesList, session, cancellationToken);
    }

    public override async Task<TEntity?> FindOneAndUpdateAsync(
        FilterDefinition<TEntity> filter,
        UpdateDefinition<TEntity> update,
        FindOneAndUpdateOptions<TEntity>? options = null)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        return await base.FindOneAndUpdateAsync(filter & OrgFilter(orgId), update, options);
    }

    public override async Task<long> UpdateOneAsync(FilterDefinition<TEntity> filter, UpdateDefinition<TEntity> update)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        return await base.UpdateOneAsync(filter & OrgFilter(orgId), update);
    }

    public override async Task<long> UpdateManyAsync(FilterDefinition<TEntity> filter, UpdateDefinition<TEntity> update)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        return await base.UpdateManyAsync(filter & OrgFilter(orgId), update);
    }

    public override async Task<long> DeleteManyAsync(Expression<Func<TEntity, bool>> predicate)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        return await base.DeleteManyAsync(CombineWithOrgFilter(predicate, orgId));
    }

    public override async Task<long> DeleteManyAsync(FilterDefinition<TEntity> filter)
    {
        var orgId = await orgContext.GetCurrentOrgIdAsync();
        return await base.DeleteManyAsync(filter & OrgFilter(orgId));
    }

    private static FilterDefinition<TEntity> OrgFilter(string orgId)
    {
        var parameter = Expression.Parameter(typeof(TEntity), "e");
        var orgEquals = Expression.Equal(
            Expression.Property(parameter, nameof(IOrganizationEntity.OrgId)),
            Expression.Constant(orgId));
        return Builders<TEntity>.Filter.Where(Expression.Lambda<Func<TEntity, bool>>(orgEquals, parameter));
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
