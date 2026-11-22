using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Bson.Serialization.Conventions;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.FindingSuppression;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Data.Serializers;

namespace VulWall.Dashboard.Extensions.Configuration;

/// <summary>
/// Configures MongoDB client, serialization, and repository registration
/// </summary>
public static class MongoDbConfiguration
{
    /// <summary>
    /// Configures MongoDB serialization settings including case-insensitive enum serializers
    /// </summary>
    public static void ConfigureSerialization()
    {
        // Register custom enum serializers that handle case-insensitive deserialization
        try
        {
            BsonSerializer.RegisterSerializer(new CaseInsensitiveEnumSerializer<AssetType>());
            BsonSerializer.RegisterSerializer(new CaseInsensitiveEnumSerializer<AssetStatus>());
            BsonSerializer.RegisterSerializer(new CaseInsensitiveEnumSerializer<Severity>());
            BsonSerializer.RegisterSerializer(new CaseInsensitiveEnumSerializer<OwnershipStatus>());
            // The scanner writes "done"; accept "completed" too so either spelling reads as Done.
            BsonSerializer.RegisterSerializer(new CaseInsensitiveEnumSerializer<ScanStatus>(
                new Dictionary<string, ScanStatus> { ["completed"] = ScanStatus.Done }));
            BsonSerializer.RegisterSerializer(new CaseInsensitiveEnumSerializer<ScanType>());
        }
        catch (BsonSerializationException)
        {
            // Serializer already registered, ignore
        }

        // Configure enum representation as string in MongoDB
        var conventionPack = new ConventionPack
        {
            new EnumRepresentationConvention(BsonType.String)
        };
        ConventionRegistry.Register("EnumStringConvention", conventionPack, _ => true);
    }

    /// <summary>
    /// Configures and registers MongoDB client and database instances
    /// </summary>
    public static void ConfigureClient(IServiceCollection services)
    {
        var mongoClient = new MongoClient(ServiceSettings.Instance.Mongo_URI);
        var database = mongoClient.GetDatabase(ServiceSettings.Instance.MongoDb);

        // Register as singletons
        services.AddSingleton<IMongoClient>(mongoClient);
        services.AddSingleton(database);
    }

    /// <summary>
    /// Registers all MongoDB repository services
    /// </summary>
    public static void RegisterRepositories(IServiceCollection services)
    {
        services.AddScoped<AssetsRepository>();
        services.AddScoped<DiscoveriesRepository>();
        services.AddScoped<OrganizationRepository>();
        services.AddScoped<UsersRepository>();
        services.AddScoped<ScansRepository>();
        services.AddScoped<FindingsRepository>();
        services.AddScoped<ScansPublicRepository>();
        services.AddScoped<FindingsPublicRepository>();
        services.AddScoped<DiscoveriesPublicRepository>();
        services.AddScoped<KnowledgeBaseRepository>();
        services.AddScoped<FindingSuppressionsRepository>();
        services.AddScoped<SystemInfoRepository>();
        services.AddScoped<ScanCoverageRepository>();
    }
}
