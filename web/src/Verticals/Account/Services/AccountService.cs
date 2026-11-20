using System.Text;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Entities.User;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Account.Services;

public enum SetupResult
{
    Created,
    AlreadySetUp
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
                PasswordHash = HashPassword(password)
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

        var passwordMatches = VerifyPassword(password, emailMatches ? user!.PasswordHash : DummyHash);
        return emailMatches && passwordMatches ? user : null;
    }

    /// <summary>Test hook: the cached flag outlives a test's throwaway database.</summary>
    internal static void ResetCacheForTests() => _adminExists = false;
}
