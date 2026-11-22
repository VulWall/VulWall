using System.Linq.Expressions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Data.Abstractions;

namespace VulWall.Dashboard.Data.Base;

public abstract class BaseMongoRepository<TEntity, TId>(IMongoDatabase database, string collectionName)
    : IRepository<TEntity, TId>
    where TEntity : class, IEntity<TId>
{
    private readonly IMongoCollection<TEntity> _collection = database.GetCollection<TEntity>(collectionName);

    protected IMongoDatabase Database => database;

    protected IMongoCollection<TEntity> Collection => _collection;

    public virtual async Task<TEntity?> GetByIdAsync(TId id)
    {
        var filter = BuildIdFilter(id);
        return await _collection.Find(filter).FirstOrDefaultAsync();
    }

    public virtual async Task<IEnumerable<TEntity>> GetAllAsync()
    {
        return await _collection.Find(_ => true).ToListAsync();
    }

    public virtual async Task<TEntity> CreateAsync(TEntity entity)
    {
        await _collection.InsertOneAsync(entity);
        return entity;
    }

    public virtual async Task<TEntity> UpdateAsync(TEntity entity)
    {
        var id = GetEntityId(entity);
        var filter = BuildIdFilter(id);
        var options = new ReplaceOptions { IsUpsert = false };

        await _collection.ReplaceOneAsync(filter, entity, options);
        return entity;
    }

    public virtual async Task<bool> DeleteAsync(TId id)
    {
        var filter = BuildIdFilter(id);
        var result = await _collection.DeleteOneAsync(filter);
        return result.DeletedCount > 0;
    }

    public virtual async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate)
    {
        return await _collection.Find(predicate).ToListAsync();
    }

    public virtual async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate, int limit, int skip)
    {
        return await _collection.Find(predicate)
            .Skip(skip)
            .Limit(limit)
            .ToListAsync();
    }

    public virtual async Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate,
        Expression<Func<TEntity, object>> orderByProperty, Common.Contracts.Enums.SortDirection sortDirection = Common.Contracts.Enums.SortDirection.Ascending,
        int limit = 0, int skip = 0)
    {
        var sortDefinition = sortDirection == Common.Contracts.Enums.SortDirection.Ascending
            ? Builders<TEntity>.Sort.Ascending(orderByProperty)
            : Builders<TEntity>.Sort.Descending(orderByProperty);

        var query = _collection.Find(predicate).Sort(sortDefinition);

        if (skip > 0)
            query = query.Skip(skip);
        if (limit > 0)
            query = query.Limit(limit);

        return await query.ToListAsync();
    }

    public virtual async Task<TEntity?> GetByFieldAsync(string fieldName, object value)
    {
        var filter = Builders<TEntity>.Filter.Eq(fieldName, value);
        return await _collection.Find(filter).FirstOrDefaultAsync();
    }

    public virtual async Task<long> CountAsync(Expression<Func<TEntity, bool>> predicate)
    {
        return await _collection.CountDocumentsAsync(predicate);
    }

    public virtual async Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> predicate)
    {
        return await _collection.Find(predicate).Limit(1).AnyAsync();
    }

    public virtual async Task<IEnumerable<TEntity>> CreateManyAsync(IEnumerable<TEntity> entities)
    {
        await _collection.InsertManyAsync(entities);
        return entities;
    }

    public virtual Task CreateManyAsync(IEnumerable<TEntity> entities, IClientSessionHandle session, CancellationToken cancellationToken = default) =>
        _collection.InsertManyAsync(session, entities, cancellationToken: cancellationToken);

    public virtual async Task<TEntity?> FindOneAndUpdateAsync(
        FilterDefinition<TEntity> filter,
        UpdateDefinition<TEntity> update,
        FindOneAndUpdateOptions<TEntity>? options = null)
    {
        return await _collection.FindOneAndUpdateAsync(filter, update, options);
    }

    public virtual async Task<long> DeleteManyAsync(Expression<Func<TEntity, bool>> predicate)
    {
        var result = await _collection.DeleteManyAsync(predicate);
        return result.DeletedCount;
    }

    public virtual async Task<long> DeleteManyAsync(FilterDefinition<TEntity> filter)
    {
        var result = await _collection.DeleteManyAsync(filter);
        return result.DeletedCount;
    }

    /// <summary>Partial update ($set, $pull, ...) of the first match. Returns the matched count.</summary>
    public virtual async Task<long> UpdateOneAsync(FilterDefinition<TEntity> filter, UpdateDefinition<TEntity> update)
    {
        var result = await _collection.UpdateOneAsync(filter, update);
        return result.MatchedCount;
    }

    /// <summary>Partial update ($set, $pull, ...) of every match. Returns the matched count.</summary>
    public virtual async Task<long> UpdateManyAsync(FilterDefinition<TEntity> filter, UpdateDefinition<TEntity> update)
    {
        var result = await _collection.UpdateManyAsync(filter, update);
        return result.MatchedCount;
    }

    // Helper methods that work because TEntity implements IEntity<TId>
    protected virtual FilterDefinition<TEntity> BuildIdFilter(TId id)
    {
        if (typeof(TId) == typeof(string))
        {
            // If the string is a valid ObjectId, use ObjectId type in the filter; otherwise, use the string as-is
            var idString = id.ToString();
            return ObjectId.TryParse(idString, out var objectId)
                ? Builders<TEntity>.Filter.Eq("_id", objectId)
                : Builders<TEntity>.Filter.Eq("_id", idString);
        }

        if (typeof(TId) == typeof(ObjectId))
        {
            if (id is ObjectId objectId)
                return Builders<TEntity>.Filter.Eq("_id", objectId);
            throw new InvalidCastException($"Cannot cast id of type {id?.GetType()} to ObjectId.");
        }
        return Builders<TEntity>.Filter.Eq("_id", id);
    }

    protected virtual TId GetEntityId(TEntity entity)
    {
        return entity.Id; // ✅ Works because TEntity implements IEntity<TId>
    }

    // Additional helper methods for common operations
    protected virtual FilterDefinition<TEntity> BuildFieldFilter(string fieldName, object value)
    {
        return Builders<TEntity>.Filter.Eq(fieldName, value);
    }

    protected virtual FilterDefinition<TEntity> BuildRangeFilter(string fieldName, object minValue, object maxValue)
    {
        return Builders<TEntity>.Filter.And(
            Builders<TEntity>.Filter.Gte(fieldName, minValue),
            Builders<TEntity>.Filter.Lte(fieldName, maxValue)
        );
    }
}
