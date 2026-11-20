using VulWall.Dashboard.Account.Services;
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
await MongoDbIndexManager.EnsureIndexesAsync(database, app.Logger);
await DefaultOrganization.EnsureExistsAsync(new OrganizationRepository(database));

using (var scope = app.Services.CreateScope())
{
    if (!await scope.ServiceProvider.GetRequiredService<AccountService>().AdminExistsAsync())
    {
        var token = app.Services.GetRequiredService<SetupToken>().Value;
        app.Logger.LogWarning(
            "First-run setup: open http://localhost:{Port}/setup?token={Token} (use your server's address if it is not this machine)",
            port, token);
    }
}

await app.RunAsync();