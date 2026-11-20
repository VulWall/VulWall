using Microsoft.Extensions.Caching.Memory;
using MongoDB.Driver;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;

namespace VulWall.Dashboard.Common.Services;

/// <summary>
/// Caches the full Knowledge Base entry list with a 1-hour TTL.
/// The KB is ~84 static documents shared across all organizations — loading it fresh
/// on every page request is wasteful. Uses IMongoDatabase directly (singleton-safe)
/// instead of the scoped KnowledgeBaseRepository.
/// </summary>
public class KnowledgeBaseCacheService(IMongoDatabase database, IMemoryCache cache)
{
    private const string CacheKey = "knowledge_base_all";
    private const string CollectionName = "knowledge_base";

    public async Task<IEnumerable<KnowledgeBaseEntry>> GetAllAsync()
    {
        if (cache.TryGetValue(CacheKey, out IEnumerable<KnowledgeBaseEntry>? cached))
            return cached!;

        var collection = database.GetCollection<KnowledgeBaseEntry>(CollectionName);
        var filter = Builders<KnowledgeBaseEntry>.Filter.Eq(kb => kb.Published, true);
        var entries = await collection.Find(filter).ToListAsync();

        var cacheOptions = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1)
        };

        cache.Set(CacheKey, entries, cacheOptions);

        return entries;
    }
}
