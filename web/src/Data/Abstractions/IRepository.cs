using System.Linq.Expressions;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Data.Abstractions;

public interface IRepository<TEntity, TId> where TEntity : class
{
    // Core CRUD operations
    Task<TEntity?> GetByIdAsync(TId id);
    Task<IEnumerable<TEntity>> GetAllAsync();
    Task<TEntity> CreateAsync(TEntity entity);
    Task<TEntity> UpdateAsync(TEntity entity);
    Task<bool> DeleteAsync(TId id);

    // Querying
    Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate);
    Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate, int limit, int skip);

    Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate,
        Expression<Func<TEntity, object>> orderByProperty, Common.Contracts.Enums.SortDirection sortDirection = Common.Contracts.Enums.SortDirection.Ascending,
        int limit = 0, int skip = 0);

    // Common MongoDB operations
    Task<TEntity?> GetByFieldAsync(string fieldName, object value);
    Task<long> CountAsync(Expression<Func<TEntity, bool>> predicate);
    Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> predicate);

    // Bulk operations (when needed)
    Task<IEnumerable<TEntity>> CreateManyAsync(IEnumerable<TEntity> entities);
}
