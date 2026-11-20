using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Account;
using VulWall.Dashboard.Account.Models;
using VulWall.Dashboard.Account.Services;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Services.RateLimiter;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Account;

public class PasswordTests
{
    [Fact]
    public void HashPassword_ProducesBcryptHashThatVerifies()
    {
        var hash = AccountService.HashPassword("correct horse battery");

        Assert.StartsWith("$2", hash);
        Assert.DoesNotContain("correct horse battery", hash);
        Assert.True(AccountService.VerifyPassword("correct horse battery", hash));
        Assert.False(AccountService.VerifyPassword("correct horse batterY", hash));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("123456789")]
    public void ValidatePassword_TooShort_ReturnsError(string? password) =>
        Assert.NotNull(AccountService.ValidatePassword(password));

    [Fact]
    public void ValidatePassword_TenCharacters_IsAccepted() =>
        Assert.Null(AccountService.ValidatePassword("1234567890"));

    [Fact]
    public void ValidatePassword_LongerThanBcryptLimit_ReturnsError() =>
        Assert.NotNull(AccountService.ValidatePassword(new string('a', 73)));
}

[Collection(MongoCollection.Name)]
public class AccountServiceTests(MongoFixture mongo)
{
    private (AccountService Service, IMongoDatabase Db) Create()
    {
        AccountService.ResetCacheForTests();
        var db = mongo.NewDatabase();
        var service = new AccountService(new UsersRepository(db), new OrganizationRepository(db),
            NullLogger<AccountService>.Instance);
        return (service, db);
    }

    [Fact]
    public async Task CreateAdmin_StoresHashedPasswordAndNamesDefaultOrg()
    {
        var (service, db) = Create();
        await DefaultOrganization.EnsureExistsAsync(new OrganizationRepository(db));

        Assert.False(await service.AdminExistsAsync());
        var result = await service.CreateAdminAsync(" Admin@Example.com ", "a-long-password", "Acme");

        Assert.Equal(SetupResult.Created, result);
        Assert.True(await service.AdminExistsAsync());
        var user = await db.GetCollection<BsonDocument>("users").Find(FilterDefinition<BsonDocument>.Empty).SingleAsync();
        Assert.Equal("admin@example.com", user["email"].AsString);
        Assert.NotEqual("a-long-password", user["password_hash"].AsString);
        var org = await DefaultOrganization.GetAsync(new OrganizationRepository(db));
        Assert.Equal("Acme", org!.CompanyName);
        Assert.Equal("admin@example.com", org.OwnerEmail);
    }

    [Fact]
    public async Task CreateAdmin_WhenAdminExists_ReturnsAlreadySetUp()
    {
        var (service, db) = Create();
        await service.CreateAdminAsync("a@example.com", "a-long-password", null);

        var second = await service.CreateAdminAsync("b@example.com", "another-password", null);

        Assert.Equal(SetupResult.AlreadySetUp, second);
        Assert.Equal(1, await db.GetCollection<BsonDocument>("users").CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
    }

    [Fact]
    public async Task CreateAdmin_ConcurrentRequests_CreateExactlyOneAdmin()
    {
        var (_, db) = Create();
        var services = Enumerable.Range(0, 5).Select(_ => new AccountService(new UsersRepository(db),
            new OrganizationRepository(db), NullLogger<AccountService>.Instance)).ToList();

        var results = await Task.WhenAll(services.Select((s, i) => s.CreateAdminAsync($"u{i}@example.com", "a-long-password", null)));

        Assert.Single(results, r => r == SetupResult.Created);
        Assert.Equal(1, await db.GetCollection<BsonDocument>("users").CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
    }

    [Fact]
    public async Task ValidateCredentials_ChecksEmailAndPassword()
    {
        var (service, _) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);

        Assert.NotNull(await service.ValidateCredentialsAsync("ADMIN@example.com", "a-long-password"));
        Assert.Null(await service.ValidateCredentialsAsync("admin@example.com", "wrong-password"));
        Assert.Null(await service.ValidateCredentialsAsync("other@example.com", "a-long-password"));
    }

    [Fact]
    public async Task SecurityStamp_IsSetOnCreateAndRotationInvalidatesIt()
    {
        var (service, _) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);
        var original = (await service.ValidateCredentialsAsync("admin@example.com", "a-long-password"))!.SecurityStamp;

        Assert.False(string.IsNullOrEmpty(original));
        Assert.True(await service.IsSecurityStampCurrentAsync(original));

        var rotated = await service.RotateSecurityStampAsync();

        Assert.NotEqual(original, rotated);
        Assert.False(await service.IsSecurityStampCurrentAsync(original));
        Assert.True(await service.IsSecurityStampCurrentAsync(rotated));
    }

    [Fact]
    public async Task SecurityStamp_AccountWithoutStamp_AcceptsCookieWithoutStampUntilRotated()
    {
        var (service, db) = Create();
        await db.GetCollection<BsonDocument>("users").InsertOneAsync(new BsonDocument
        {
            { "_id", "admin" }, { "email", "admin@example.com" },
            { "password_hash", AccountService.HashPassword("a-long-password") }
        });

        Assert.True(await service.IsSecurityStampCurrentAsync(null));

        await service.RotateSecurityStampAsync();

        Assert.False(await service.IsSecurityStampCurrentAsync(null));
    }

    [Fact]
    public async Task SecurityStamp_NoAdmin_RejectsEveryCookie()
    {
        var (service, _) = Create();

        Assert.False(await service.IsSecurityStampCurrentAsync(null));
        Assert.False(await service.IsSecurityStampCurrentAsync(""));
    }

    [Fact]
    public async Task ChangePassword_WrongCurrentPassword_ChangesNothing()
    {
        var (service, _) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);
        var stamp = await service.GetSecurityStampAsync();

        var (result, _) = await service.ChangePasswordAsync("wrong-password", "a-new-long-password");

        Assert.Equal(ChangePasswordResult.WrongCurrentPassword, result);
        Assert.NotNull(await service.ValidateCredentialsAsync("admin@example.com", "a-long-password"));
        Assert.True(await service.IsSecurityStampCurrentAsync(stamp));
    }

    [Fact]
    public async Task ChangePassword_TooShort_IsRejected()
    {
        var (service, _) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);

        var (result, _) = await service.ChangePasswordAsync("a-long-password", "short");

        Assert.Equal(ChangePasswordResult.InvalidNewPassword, result);
        Assert.NotNull(await service.ValidateCredentialsAsync("admin@example.com", "a-long-password"));
    }

    [Fact]
    public async Task ChangePassword_Correct_ChangesPasswordAndRotatesStamp()
    {
        var (service, _) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);
        var oldStamp = await service.GetSecurityStampAsync();

        var (result, user) = await service.ChangePasswordAsync("a-long-password", "a-new-long-password");

        Assert.Equal(ChangePasswordResult.Changed, result);
        Assert.Null(await service.ValidateCredentialsAsync("admin@example.com", "a-long-password"));
        Assert.NotNull(await service.ValidateCredentialsAsync("admin@example.com", "a-new-long-password"));
        Assert.False(await service.IsSecurityStampCurrentAsync(oldStamp));
        Assert.True(await service.IsSecurityStampCurrentAsync(user!.SecurityStamp));
    }

    [Fact]
    public async Task EnsureDefaultOrganization_CreatesOneOrgWithScanCron()
    {
        var (_, db) = Create();
        var repo = new OrganizationRepository(db);

        var first = await DefaultOrganization.EnsureExistsAsync(repo);
        var second = await DefaultOrganization.EnsureExistsAsync(repo);

        Assert.Equal(first.Id, second.Id);
        Assert.Equal(DefaultOrganization.DefaultName, first.CompanyName);
        Assert.False(string.IsNullOrWhiteSpace(first.ScanSettings?.ScanCron));
        Assert.Equal(1, await db.GetCollection<BsonDocument>("organizations").CountDocumentsAsync(FilterDefinition<BsonDocument>.Empty));
    }
}

[Collection(MongoCollection.Name)]
public class AccountControllerTests(MongoFixture mongo)
{
    private const string SignedInPrincipalKey = "test:signed-in-principal";

    private sealed class NoopAuthService : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(AuthenticateResult.NoResult());
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
        {
            context.Items[SignedInPrincipalKey] = principal; // the principal the cookie would carry
            return Task.CompletedTask;
        }
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;
    }

    // HttpContextAccessor stores its context in a static AsyncLocal shared across tests.
    private sealed class FixedAccessor(HttpContext context) : IHttpContextAccessor
    {
        public HttpContext? HttpContext { get; set; } = context;
    }

    private sealed class NoopTempDataProvider : ITempDataProvider
    {
        public IDictionary<string, object> LoadTempData(HttpContext context) => new Dictionary<string, object>();
        public void SaveTempData(HttpContext context, IDictionary<string, object> values) { }
    }

    private const string Token = "test-setup-token";

    private (AccountController Controller, AccountService Service) Create(
        IMongoDatabase? db = null, IMemoryCache? cache = null, string ip = "203.0.113.7")
    {
        AccountService.ResetCacheForTests();
        db ??= mongo.NewDatabase();
        var service = new AccountService(new UsersRepository(db), new OrganizationRepository(db),
            NullLogger<AccountService>.Instance);
        var httpContext = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection()
                .AddSingleton<IAuthenticationService, NoopAuthService>()
                .BuildServiceProvider()
        };
        httpContext.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(ip);
        var accessor = new FixedAccessor(httpContext);
        var controller = new AccountController(service, new SetupToken(Token),
            new IpRateLimiterService(cache ?? new MemoryCache(new MemoryCacheOptions()), accessor),
            NullLogger<AccountController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = httpContext },
            TempData = new TempDataDictionary(httpContext, new NoopTempDataProvider())
        };
        return (controller, service);
    }

    [Fact]
    public void Logout_RequiresAuthentication()
    {
        // A class-level [AllowAnonymous] would override [Authorize] on Logout.
        Assert.Empty(typeof(AccountController).GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute), true));
        var logout = typeof(AccountController).GetMethod(nameof(AccountController.Logout))!;
        Assert.NotEmpty(logout.GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute), true));
    }

    [Fact]
    public async Task SetupGet_NoAdmin_CorrectToken_ShowsSetupPageWithToken()
    {
        var (controller, _) = Create();

        var view = Assert.IsType<ViewResult>(await controller.Setup(Token));
        Assert.Equal(Token, Assert.IsType<SetupInput>(view.Model).Token);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("wrong-token")]
    [InlineData("test-setup-tokeN")]
    public async Task SetupGet_MissingOrWrongToken_Returns404(string? token)
    {
        var (controller, _) = Create();

        Assert.IsType<NotFoundResult>(await controller.Setup(token));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("wrong-token")]
    public async Task SetupPost_MissingOrWrongToken_Returns404AndCreatesNoAdmin(string? token)
    {
        var (controller, service) = Create();

        var result = await controller.Setup(new SetupInput
        {
            Email = "attacker@example.com",
            Password = "attacker-password",
            ConfirmPassword = "attacker-password",
            Token = token
        });

        Assert.IsType<NotFoundResult>(result);
        Assert.False(await service.AdminExistsAsync());
    }

    [Fact]
    public async Task SetupPost_CorrectToken_CreatesAdmin()
    {
        var (controller, service) = Create();

        var result = await controller.Setup(new SetupInput
        {
            Email = "admin@example.com",
            Password = "a-long-password",
            ConfirmPassword = "a-long-password",
            Token = Token
        });

        Assert.Equal("/", Assert.IsType<RedirectResult>(result).Url);
        Assert.NotNull(await service.ValidateCredentialsAsync("admin@example.com", "a-long-password"));
    }

    [Fact]
    public async Task SetupPost_ValidationError_KeepsTokenForTheNextSubmit()
    {
        var (controller, _) = Create();
        var input = new SetupInput { Email = "admin@example.com", Password = "short", ConfirmPassword = "short", Token = Token };

        var view = Assert.IsType<ViewResult>(await controller.Setup(input));

        Assert.Equal(Token, Assert.IsType<SetupInput>(view.Model).Token);
    }

    [Fact]
    public async Task SetupGet_AdminExists_RedirectsToLoginEvenWithToken()
    {
        var (controller, service) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);

        var redirect = Assert.IsType<RedirectResult>(await controller.Setup(Token));
        Assert.Equal("/login", redirect.Url);
    }

    [Fact]
    public async Task SetupPost_AdminExists_DoesNotCreateAnotherAdmin()
    {
        var (controller, service) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);

        var result = await controller.Setup(new SetupInput
        {
            Email = "attacker@example.com",
            Password = "attacker-password",
            ConfirmPassword = "attacker-password",
            Token = Token
        });

        Assert.Equal("/login", Assert.IsType<RedirectResult>(result).Url);
        Assert.Null(await service.ValidateCredentialsAsync("attacker@example.com", "attacker-password"));
    }

    [Fact]
    public async Task SetupPost_ShortPassword_ReturnsViewWithError()
    {
        var (controller, service) = Create();

        var result = await controller.Setup(new SetupInput
        {
            Email = "admin@example.com",
            Password = "short",
            ConfirmPassword = "short",
            Token = Token
        });

        Assert.IsType<ViewResult>(result);
        Assert.False(controller.ModelState.IsValid);
        Assert.False(await service.AdminExistsAsync());
    }

    [Fact]
    public async Task LoginGet_NoAdmin_ShowsSetupPendingPageWithoutToken()
    {
        var (controller, _) = Create();

        var view = Assert.IsType<ViewResult>(await controller.Login(returnUrl: null));
        Assert.Equal("SetupPending", view.ViewName);
        Assert.Null(view.Model);
    }

    [Fact]
    public async Task LoginPost_RepeatedFailures_AreRateLimited()
    {
        var (controller, service) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);

        // Each real request gets fresh ModelState; clear it to simulate separate requests.
        for (var i = 0; i < 5; i++)
        {
            await controller.Login(new LoginInput { Email = "admin@example.com", Password = "wrong-password" });
            controller.ModelState.Clear();
        }

        // Even the right password is refused while the IP is locked out.
        var result = await controller.Login(new LoginInput { Email = "admin@example.com", Password = "a-long-password" });

        Assert.IsType<ViewResult>(result);
        Assert.Contains(controller.ModelState[string.Empty]!.Errors, e => e.ErrorMessage.Contains("Too many"));
    }

    [Fact]
    public async Task Logout_RotatesSecurityStamp()
    {
        var (controller, service) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);
        var stamp = await service.GetSecurityStampAsync();

        await controller.Logout();

        Assert.False(await service.IsSecurityStampCurrentAsync(stamp));
    }

    [Fact]
    public async Task ChangePassword_Success_ReissuesCookieWithNewStamp()
    {
        var (controller, service) = Create();
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);
        var oldStamp = await service.GetSecurityStampAsync();

        var result = await controller.ChangePassword(new ChangePasswordInput
        {
            CurrentPassword = "a-long-password",
            NewPassword = "a-new-long-password",
            ConfirmNewPassword = "a-new-long-password"
        });

        Assert.Equal("/settings", Assert.IsType<RedirectResult>(result).Url);
        var signedIn = Assert.IsType<ClaimsPrincipal>(controller.HttpContext.Items[SignedInPrincipalKey]);
        var cookieStamp = signedIn.FindFirst(AccountService.SecurityStampClaim)?.Value;
        Assert.NotEqual(oldStamp, cookieStamp);
        Assert.True(await service.IsSecurityStampCurrentAsync(cookieStamp));
    }

    [Fact]
    public async Task LoginPost_FailuresFromManyIps_HitTheAccountLimit()
    {
        var db = mongo.NewDatabase();
        var cache = new MemoryCache(new MemoryCacheOptions());
        var (_, service) = Create(db, cache);
        await service.CreateAdminAsync("admin@example.com", "a-long-password", null);

        // 20 failures spread over 10 IPs: no IP reaches its own limit of 5.
        for (var i = 0; i < 20; i++)
        {
            var (c, _) = Create(db, cache, $"198.51.100.{i % 10}");
            await c.Login(new LoginInput { Email = "admin@example.com", Password = "wrong-password" });
        }

        var (fresh, _) = Create(db, cache, "192.0.2.1");
        var result = await fresh.Login(new LoginInput { Email = "admin@example.com", Password = "a-long-password" });

        Assert.IsType<ViewResult>(result);
        Assert.Contains(fresh.ModelState[string.Empty]!.Errors, e => e.ErrorMessage.Contains("Too many"));
    }
}

public class SetupTokenTests
{
    [Fact]
    public void Generated_IsRandom32HexChars()
    {
        var a = new SetupToken(null);
        var b = new SetupToken("  ");

        Assert.Matches("^[0-9a-f]{32}$", a.Value);
        Assert.NotEqual(a.Value, b.Value);
        Assert.True(a.Matches(a.Value));
    }

    [Fact]
    public void Configured_OverridesGeneratedToken()
    {
        var token = new SetupToken(" unattended-install-token ");

        Assert.Equal("unattended-install-token", token.Value);
        Assert.True(token.Matches("unattended-install-token"));
        Assert.False(token.Matches("unattended-install-toke"));
        Assert.False(token.Matches(null));
    }
}
