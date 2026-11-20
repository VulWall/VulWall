using System.Text;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.User;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Account.Services;

public enum SetupResult
{
    Created,
    AlreadySetUp
}

public enum ChangePasswordResult
{
    Changed,
    WrongCurrentPassword,
    InvalidNewPassword
}

/// <summary>
/// Local single-admin accounts: first-run setup and password login.
/// </summary>
public class AccountService(
    UsersRepository usersRepository,
    OrganizationRepository organizationRepository,
    ILogger<AccountService> logger)
{
    public const int MinPasswordLength = 10;

    /// <summary>BCrypt only uses the first 72 bytes of a password; reject longer ones instead of truncating silently.</summary>
    public const int MaxPasswordBytes = 72;

    private const int BcryptWorkFactor = 12;

    // Compared against when the email does not match, so a wrong email costs the same time
    // as a wrong password.
    private static readonly string DummyHash = BCrypt.Net.BCrypt.HashPassword("vulwall-dummy-password", BcryptWorkFactor);

    // Once an admin exists it is never removed by the app, so a true result can be cached
    // for the process lifetime. False is always re-checked.
    private static volatile bool _adminExists;

    /// <summary>Claim type that carries the security stamp in the auth cookie.</summary>
    public const string SecurityStampClaim = "vulwall:security_stamp";

    // The cookie handler checks the stamp on every request; cache it briefly so that is not a
    // database read per request. Rotation clears it, so this process sees a change at once.
    private static readonly TimeSpan StampCacheTtl = TimeSpan.FromSeconds(30);
    private sealed record StampCacheEntry(string? Stamp, DateTime Until);

    private static readonly Lock StampLock = new();
    private static StampCacheEntry? _stampCache;
    // Bumped on every rotation, so a refill that read the database before a rotation does not
    // write the old stamp back.
    private static long _stampVersion;

    public async Task<bool> AdminExistsAsync()
    {
        if (_adminExists)
            return true;

        _adminExists = await usersRepository.ExistsAsync(u => u.Id == User.AdminId);
        return _adminExists;
    }

    /// <summary>Returns an error message, or null when the password is acceptable.</summary>
    public static string? ValidatePassword(string? password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < MinPasswordLength)
            return $"Use at least {MinPasswordLength} characters.";
        if (Encoding.UTF8.GetByteCount(password) > MaxPasswordBytes)
            return $"Use at most {MaxPasswordBytes} bytes (about {MaxPasswordBytes} plain characters).";
        return null;
    }

    public static string HashPassword(string password) =>
        BCrypt.Net.BCrypt.HashPassword(password, BcryptWorkFactor);

    public static bool VerifyPassword(string password, string hash) =>
        BCrypt.Net.BCrypt.Verify(password, hash);

    /// <summary>
    /// Creates the single admin and names the default organization. The caller validates input.
    /// Returns AlreadySetUp when an admin exists, including when a concurrent request won the race.
    /// </summary>
    public async Task<SetupResult> CreateAdminAsync(string email, string password, string? organizationName)
    {
        if (await AdminExistsAsync())
            return SetupResult.AlreadySetUp;

        var normalizedEmail = email.Trim().ToLowerInvariant();
        try
        {
            await usersRepository.CreateAsync(new User
            {
                Email = normalizedEmail,
                PasswordHash = HashPassword(password),
                SecurityStamp = NewSecurityStamp()
            });
        }
        catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
        {
            _adminExists = true;
            return SetupResult.AlreadySetUp;
        }

        _adminExists = true;
        logger.LogInformation("Created the admin account");

        var org = await DefaultOrganization.GetAsync(organizationRepository);
        if (org != null)
        {
            org.CompanyName = string.IsNullOrWhiteSpace(organizationName) ? org.CompanyName : organizationName.Trim();
            org.OwnerEmail = normalizedEmail;
            org.UpdatedAt = DateTime.UtcNow;
            await organizationRepository.UpdateAsync(org);
        }

        return SetupResult.Created;
    }

    /// <summary>Returns the user when the email and password match, otherwise null.</summary>
    public async Task<User?> ValidateCredentialsAsync(string email, string password)
    {
        var normalizedEmail = email.Trim().ToLowerInvariant();
        var user = await usersRepository.GetByIdAsync(User.AdminId);
        var emailMatches = user != null && user.Email == normalizedEmail;

        var passwordMatches = await BcryptGate.VerifyAsync(password, emailMatches ? user!.PasswordHash : DummyHash);
        return emailMatches && passwordMatches ? user : null;
    }

    /// <summary>
    /// The admin's current stamp: empty for an account created before stamps existed, null when
    /// there is no admin (every cookie is then invalid).
    /// </summary>
    public async Task<string?> GetSecurityStampAsync()
    {
        long version;
        lock (StampLock)
        {
            if (_stampCache is { } cached && cached.Until > DateTime.UtcNow)
                return cached.Stamp;
            version = _stampVersion;
        }

        var user = await usersRepository.GetByIdAsync(User.AdminId);
        var stamp = user == null ? null : user.SecurityStamp ?? string.Empty;
        lock (StampLock)
        {
            if (version == _stampVersion)
                _stampCache = new StampCacheEntry(stamp, DateTime.UtcNow + StampCacheTtl);
        }
        return stamp;
    }

    /// <summary>Invalidates every auth cookie issued so far. Returns the new stamp.</summary>
    public async Task<string> RotateSecurityStampAsync()
    {
        var stamp = NewSecurityStamp();
        await usersRepository.FindOneAndUpdateAsync(
            Builders<User>.Filter.Eq(u => u.Id, User.AdminId),
            Builders<User>.Update.Set(u => u.SecurityStamp, stamp));
        InvalidateStampCache();
        return stamp;
    }

    /// <summary>
    /// Changes the admin password after checking the current one, and rotates the security stamp
    /// so every other session is signed out.
    /// </summary>
    public async Task<(ChangePasswordResult Result, User? User)> ChangePasswordAsync(string currentPassword, string newPassword)
    {
        var user = await usersRepository.GetByIdAsync(User.AdminId);
        if (user == null || !await BcryptGate.VerifyAsync(currentPassword, user.PasswordHash))
            return (ChangePasswordResult.WrongCurrentPassword, null);

        if (ValidatePassword(newPassword) != null)
            return (ChangePasswordResult.InvalidNewPassword, null);

        var stamp = NewSecurityStamp();
        var updated = await usersRepository.FindOneAndUpdateAsync(
            Builders<User>.Filter.Eq(u => u.Id, User.AdminId),
            Builders<User>.Update
                .Set(u => u.PasswordHash, HashPassword(newPassword))
                .Set(u => u.SecurityStamp, stamp),
            new FindOneAndUpdateOptions<User> { ReturnDocument = ReturnDocument.After });
        InvalidateStampCache();
        logger.LogInformation("Changed the admin password");
        return (ChangePasswordResult.Changed, updated);
    }

    /// <summary>True when the stamp in a cookie still matches the admin's current stamp.</summary>
    public async Task<bool> IsSecurityStampCurrentAsync(string? cookieStamp)
    {
        var current = await GetSecurityStampAsync();
        return current != null && current == (cookieStamp ?? string.Empty);
    }

    private static void InvalidateStampCache()
    {
        lock (StampLock)
        {
            _stampVersion++;
            _stampCache = null;
        }
    }

    private static string NewSecurityStamp() => Guid.NewGuid().ToString("N");

    /// <summary>Test hook: the cached values outlive a test's throwaway database.</summary>
    internal static void ResetCacheForTests()
    {
        _adminExists = false;
        InvalidateStampCache();
    }
}
