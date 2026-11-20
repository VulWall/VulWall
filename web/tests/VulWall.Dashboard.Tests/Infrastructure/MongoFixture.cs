using EphemeralMongo;
using MongoDB.Driver;
using VulWall.Dashboard.Extensions.Configuration;

namespace VulWall.Dashboard.Tests.Infrastructure;

/// <summary>
/// Starts one throwaway mongod for the whole test run (EphemeralMongo downloads and caches the
/// binary on first use). Each test asks for its own database so tests stay independent.
/// </summary>
public sealed class MongoFixture : IAsyncLifetime
{
    private IMongoRunner? _runner;
    private MongoClient? _client;

    static MongoFixture() => MongoDbConfiguration.ConfigureSerialization();

    public async Task InitializeAsync()
    {
        _runner = await MongoRunner.RunAsync(new MongoRunnerOptions());
        _client = new MongoClient(_runner.ConnectionString);
    }

    public IMongoDatabase NewDatabase() => _client!.GetDatabase($"test_{Guid.NewGuid():N}");

    public Task DisposeAsync()
    {
        _runner?.Dispose();
        return Task.CompletedTask;
    }
}

[CollectionDefinition(Name)]
public sealed class MongoCollection : ICollectionFixture<MongoFixture>
{
    public const string Name = "mongo";
}
