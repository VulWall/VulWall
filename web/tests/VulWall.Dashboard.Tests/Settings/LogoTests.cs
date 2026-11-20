using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Entities.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings;
using VulWall.Dashboard.Settings.Services;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Settings;

public class LogoImageTests
{
    private static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2];
    private static readonly byte[] Jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2];

    [Fact]
    public void Detect_ReadsTheMagicBytes()
    {
        Assert.Equal("image/png", LogoImage.Detect(Png));
        Assert.Equal("image/jpeg", LogoImage.Detect(Jpeg));
        Assert.Null(LogoImage.Detect("GIF89a"u8));
        Assert.Null(LogoImage.Detect([0xFF, 0xD8]));
        Assert.Null(LogoImage.Detect([]));
    }

    [Fact]
    public void GetLogoContentType_PrefersTheStoredType_ElseDetects()
    {
        Assert.Null(new Organization().GetLogoContentType());
        Assert.Null(new Organization { Logo = [], LogoContentType = "image/png" }.GetLogoContentType());
        Assert.Equal("image/jpeg", new Organization { Logo = Jpeg, LogoContentType = "image/jpeg" }.GetLogoContentType());
        // Logos stored before logo_content_type existed
        Assert.Equal("image/jpeg", new Organization { Logo = Jpeg }.GetLogoContentType());
        Assert.Equal("image/png", new Organization { Logo = Png }.GetLogoContentType());
        // An unexpected stored value is not served
        Assert.Equal("image/jpeg", new Organization { Logo = Jpeg, LogoContentType = "text/html" }.GetLogoContentType());
    }
}

[Collection(MongoCollection.Name)]
public class LogoUploadTests(MongoFixture mongo)
{
    private static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2];
    private static readonly byte[] Jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2];

    private sealed class RepositoryOrganizationContext(OrganizationRepository repo, string orgId) : IOrganizationContext
    {
        public Task<string> GetCurrentOrgIdAsync() => Task.FromResult(orgId);
        public async Task<Organization> GetCurrentOrganizationAsync() => (await repo.GetByIdAsync(orgId))!;
    }

    private sealed class NoTempDataProvider : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }

    private async Task<(SettingsController Controller, IMongoDatabase Db)> CreateAsync()
    {
        var db = mongo.NewDatabase();
        var repo = new OrganizationRepository(db);
        var org = await DefaultOrganization.EnsureExistsAsync(repo);
        var controller = new SettingsController(NullLogger<SettingsController>.Instance,
            new RepositoryOrganizationContext(repo, org.Id), new SettingsService(repo));
        var http = new DefaultHttpContext();
        controller.ControllerContext = new ControllerContext { HttpContext = http };
        controller.TempData = new TempDataDictionary(http, new NoTempDataProvider());
        return (controller, db);
    }

    private static IFormFile Upload(byte[] bytes, string contentType) =>
        new FormFile(new MemoryStream(bytes), 0, bytes.Length, "logo", "logo")
        {
            Headers = new HeaderDictionary(),
            ContentType = contentType
        };

    [Theory]
    [InlineData("png", "image/png")]
    [InlineData("jpeg", "image/jpeg")]
    public async Task UploadedLogo_IsServedWithItsOwnType(string kind, string expected)
    {
        var (controller, db) = await CreateAsync();
        var bytes = kind == "png" ? Png : Jpeg;

        await controller.UploadLogo(Upload(bytes, expected));

        var doc = await db.GetCollection<BsonDocument>("organizations").Find(FilterDefinition<BsonDocument>.Empty).SingleAsync();
        Assert.Equal(expected, doc["logo_content_type"].AsString);
        var file = Assert.IsType<FileContentResult>(await controller.GetLogo());
        Assert.Equal(expected, file.ContentType);
        Assert.Equal(bytes, file.FileContents);
    }

    [Fact]
    public async Task JpegSentAsPng_IsStoredAsJpeg()
    {
        var (controller, db) = await CreateAsync();

        await controller.UploadLogo(Upload(Jpeg, "image/png"));

        var file = Assert.IsType<FileContentResult>(await controller.GetLogo());
        Assert.Equal("image/jpeg", file.ContentType);
    }

    [Fact]
    public async Task LogoWithoutStoredType_IsDetectedFromItsBytes()
    {
        var (controller, db) = await CreateAsync();
        await db.GetCollection<BsonDocument>("organizations")
            .UpdateOneAsync(FilterDefinition<BsonDocument>.Empty, Builders<BsonDocument>.Update.Set("logo", Jpeg));

        var file = Assert.IsType<FileContentResult>(await controller.GetLogo());
        Assert.Equal("image/jpeg", file.ContentType);
    }

    [Fact]
    public async Task RemovedLogo_ClearsTheType()
    {
        var (controller, db) = await CreateAsync();
        await controller.UploadLogo(Upload(Jpeg, "image/jpeg"));

        await controller.RemoveLogo();

        var doc = await db.GetCollection<BsonDocument>("organizations").Find(FilterDefinition<BsonDocument>.Empty).SingleAsync();
        Assert.False(doc.Contains("logo_content_type"));
        Assert.IsType<NotFoundResult>(await controller.GetLogo());
    }

    [Fact]
    public async Task NonImage_IsRejected()
    {
        var (controller, db) = await CreateAsync();

        await controller.UploadLogo(Upload("GIF89a-not-allowed"u8.ToArray(), "image/png"));

        Assert.IsType<NotFoundResult>(await controller.GetLogo());
    }
}
