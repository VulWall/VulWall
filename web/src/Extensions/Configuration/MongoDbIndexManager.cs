using MongoDB.Bson;
using MongoDB.Driver;

namespace VulWall.Dashboard.Extensions.Configuration;

/// <summary>
/// Creates and maintains all application-managed MongoDB indexes.
/// Safe to call on every startup — MongoDB is idempotent for existing indexes.
/// </summary>
public static class MongoDbIndexManager
{
    public static async Task EnsureIndexesAsync(IMongoDatabase database, ILogger? logger = null)
    {
        await Task.WhenAll(
            CreateFindingIndexes(database),
            CreateScanIndexes(database, logger),
            CreateAssetIndexes(database),
            CreateTrendIndexes(database),
            CreateDiscoveryIndexes(database),
            CreateFindingSuppressionIndexes(database)
        );
    }

    private static async Task CreateFindingIndexes(IMongoDatabase database)
    {
        var collection = database.GetCollection<BsonDocument>("findings");

        await collection.Indexes.CreateManyAsync([
            // Supports: findings by scan (report generation, scan details)
            new CreateIndexModel<BsonDocument>(
                Builders<BsonDocument>.IndexKeys
                    .Ascending("org_id")
                    .Ascending("scan_ids"),
                new CreateIndexOptions { Name = "org_id_1_scan_ids_1", Background = true }),

            // Supports: open findings by severity (dashboard, recommendations, score)
            new CreateIndexModel<BsonDocument>(
                Builders<BsonDocument>.IndexKeys
                    .Ascending("org_id")
                    .Ascending("status")
                    .Ascending("severity"),
                new CreateIndexOptions { Name = "org_id_1_status_1_severity_1", Background = true }),

            // Supports: findings per asset (discoveries page)
            new CreateIndexModel<BsonDocument>(
                Builders<BsonDocument>.IndexKeys
                    .Ascending("org_id")
                    .Ascending("discovery_id"),
                new CreateIndexOptions { Name = "org_id_1_discovery_id_1", Background = true })
        ]);
    }

    /// <summary>Name of the unique partial index that allows one queued scan per organization.</summary>
    public const string OneQueuedScanPerOrgIndex = "org_id_1_queued_unique";

    private static async Task CreateScanIndexes(IMongoDatabase database, ILogger? logger)
    {
        var collection = database.GetCollection<BsonDocument>("scans");

        // UNIQUE among queued scans: at most one queued scan per organization, so concurrent
        // "Scan now" requests, or a request racing the scanner's scheduled scan, cannot queue two
        // scans (ScanTriggerService reads a duplicate-key error as "busy"). The scanner claims a
        // queued scan by changing its status, which takes it out of the index.
        try
        {
            await collection.Indexes.CreateOneAsync(new CreateIndexModel<BsonDocument>(
                Builders<BsonDocument>.IndexKeys.Ascending("org_id"),
                new CreateIndexOptions<BsonDocument>
                {
                    Name = OneQueuedScanPerOrgIndex,
                    Unique = true,
                    PartialFilterExpression = Builders<BsonDocument>.Filter.Eq("status", "queued")
                }));
        }
        catch (MongoCommandException e) when (e.Code == 11000)
        {
            // Two queued scans of one organization exist already (queued before this index).
            // The scanner starts them one after the other; the next start creates the index.
            logger?.LogWarning("Index {Index} not created yet: an organization has more than one queued scan. It is created on a later start.",
                OneQueuedScanPerOrgIndex);
        }

        await collection.Indexes.CreateManyAsync([
            // Supports: latest completed scans (dashboard widget)
            new CreateIndexModel<BsonDocument>(
                Builders<BsonDocument>.IndexKeys
                    .Ascending("org_id")
                    .Ascending("status")
                    .Descending("created_at"),
                new CreateIndexOptions { Name = "org_id_1_status_1_created_at_-1", Background = true }),

            // Supports: all scans sorted by date (scan history page with pagination)
            new CreateIndexModel<BsonDocument>(
                Builders<BsonDocument>.IndexKeys
                    .Ascending("org_id")
                    .Descending("created_at"),
                new CreateIndexOptions { Name = "org_id_1_created_at_-1", Background = true })
        ]);
    }

    private static async Task CreateAssetIndexes(IMongoDatabase database)
    {
        var collection = database.GetCollection<BsonDocument>("assets");

        await collection.Indexes.CreateOneAsync(new CreateIndexModel<BsonDocument>(
            Builders<BsonDocument>.IndexKeys.Ascending("org_id"),
            new CreateIndexOptions { Name = "org_id_1", Background = true }
        ));
    }

    private static async Task CreateTrendIndexes(IMongoDatabase database)
    {
        var collection = database.GetCollection<BsonDocument>("trends");

        await collection.Indexes.CreateOneAsync(new CreateIndexModel<BsonDocument>(
            Builders<BsonDocument>.IndexKeys.Ascending("org_id"),
            new CreateIndexOptions { Name = "org_id_1", Background = true }
        ));
    }

    private static async Task CreateDiscoveryIndexes(IMongoDatabase database)
    {
        var collection = database.GetCollection<BsonDocument>("discoveries");

        await collection.Indexes.CreateOneAsync(new CreateIndexModel<BsonDocument>(
            Builders<BsonDocument>.IndexKeys
                .Ascending("org_id")
                .Ascending("asset_type")
                .Ascending("parent_id"),
            new CreateIndexOptions { Name = "org_id_1_asset_type_1_parent_id_1", Background = true }
        ));
    }

    private static async Task CreateFindingSuppressionIndexes(IMongoDatabase database)
    {
        var collection = database.GetCollection<BsonDocument>("finding_suppressions");

        // Unique constraint prevents duplicate suppressions for the same (org, discovery, finding type) triple.
        // SuppressAsync handles MongoWriteException DuplicateKey gracefully, so concurrent inserts are safe.
        await collection.Indexes.CreateOneAsync(new CreateIndexModel<BsonDocument>(
            Builders<BsonDocument>.IndexKeys
                .Ascending("org_id")
                .Ascending("discovery_id")
                .Ascending("finding_type"),
            new CreateIndexOptions
            {
                Name = "org_id_1_discovery_id_1_finding_type_1",
                Background = true,
                Unique = true
            }
        ));
    }
}
