using MongoDB.Driver;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Extensions;
using VulWall.Dashboard.Extensions.Configuration;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddVerticalServices();
builder.Services.AddCommonServices();
builder.Services.AddMongoServices();

var port = ServiceSettings.Instance.Port;
builder.WebHost.UseUrls($"http://*:{port}");

var app = builder.Build();
app.ConfigureDashboardPipeline();

var database = app.Services.GetRequiredService<IMongoDatabase>();
await MongoDbIndexManager.EnsureIndexesAsync(database);
await DefaultOrganization.EnsureExistsAsync(new OrganizationRepository(database));

await app.RunAsync();