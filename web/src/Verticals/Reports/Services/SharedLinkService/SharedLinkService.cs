using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.SharedLink;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Reports.Models;

namespace VulWall.Dashboard.Reports.Services.SharedLinkService;

public class SharedLinkService(
    SharedLinksRepository sharedLinksRepository,
    SharedLinksPublicRepository sharedLinksPublicRepository,
    ScansRepository scansRepository)
{
    private const int MaxActiveLinks = 5;
    private const int MinPasswordLength = 8;
    private static readonly int[] AllowedExpirationDays = [1, 7, 30];

    public async Task<(SharedLink? Link, string? Error)> CreateSharedLinkAsync(
        string reportName,
        string scanId,
        string password,
        int expirationDays)
    {
        // Validate password strength
        if (string.IsNullOrWhiteSpace(password) || password.Length < MinPasswordLength)
        {
            return (null, $"Password must be at least {MinPasswordLength} characters.");
        }

        if (!password.Any(char.IsUpper) || !password.Any(char.IsLower) || !password.Any(char.IsDigit))
        {
            return (null, "Password must contain at least one uppercase letter, one lowercase letter, and one number.");
        }

        // Validate expiration days
        if (!AllowedExpirationDays.Contains(expirationDays))
        {
            return (null, "Invalid expiration days. Allowed values: 1, 7, 30");
        }

        // Validate scan exists
        var scan = await scansRepository.GetByIdAsync(scanId);
        if (scan == null)
        {
            return (null, "Scan not found");
        }

        // Check active links limit
        var activeLinksCount = await GetActiveLinksCountAsync();
        if (activeLinksCount >= MaxActiveLinks)
        {
            return (null, $"Maximum of {MaxActiveLinks} active links reached. Please revoke an existing link first.");
        }

        // Create shared link
        var sharedLink = new SharedLink
        {
            ReportName = reportName,
            ScanId = scanId,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(password),
            ExpirationDays = expirationDays
        };

        await sharedLinksRepository.CreateAsync(sharedLink);

        return (sharedLink, null);
    }

    public async Task<SharedLink?> GetSharedLinkByTokenAsync(string token)
    {
        var links = await sharedLinksPublicRepository.FindAsync(l => l.Token == token);
        return links.FirstOrDefault();
    }

    public async Task<bool> VerifyPasswordAsync(string token, string password)
    {
        var link = await GetSharedLinkByTokenAsync(token);
        if (link == null || !link.IsActive)
        {
            return false;
        }

        return await BcryptGate.VerifyAsync(password, link.PasswordHash);
    }

    public async Task<bool> RevokeSharedLinkAsync(string linkId)
    {
        var link = await sharedLinksRepository.GetByIdAsync(linkId);
        if (link == null)
        {
            return false;
        }

        link.IsRevoked = true;
        await sharedLinksRepository.UpdateAsync(link);
        return true;
    }

    public async Task<List<SharedLinkViewModel>> GetSharedLinksAsync()
    {
        var links = await sharedLinksRepository.GetAllAsync();
        var scans = await scansRepository.GetAllAsync();

        return links
            .OrderByDescending(l => l.CreatedAt)
            .Select(l =>
            {
                var scan = scans.FirstOrDefault(s => s.Id == l.ScanId);
                var expiresText = GetExpirationText(l);

                return new SharedLinkViewModel
                {
                    Id = l.Id,
                    Token = l.Token,
                    ReportName = l.ReportName,
                    ScanName = scan != null ? $"{scan.Type} Scan - {scan.CreatedAt:MMM dd, yyyy}" : "Unknown Scan",
                    Type = "Summary",
                    TypeBadgeClass = "badge-primary",
                    Created = l.CreatedAt,
                    Expires = expiresText,
                    IsExpired = l.IsExpired,
                    IsRevoked = l.IsRevoked
                };
            })
            .ToList();
    }

    public async Task<int> GetActiveLinksCountAsync()
    {
        var links = await sharedLinksRepository.GetAllAsync();
        return links.Count(l => l.IsActive);
    }

    public async Task<SummaryReportViewModel?> GetSharedReportDataAsync(string token)
    {
        var link = await GetSharedLinkByTokenAsync(token);
        if (link == null || !link.IsActive)
        {
            return null;
        }

        // We need to get data without org scoping - use public repository approach
        // For now, we'll return the link's scan ID and let the controller handle building the report
        return null; // Will be handled differently in controller
    }

    private static string GetExpirationText(SharedLink link)
    {
        if (link.IsRevoked)
        {
            return "Revoked";
        }

        if (link.IsExpired)
        {
            return "Expired";
        }

        var remaining = link.ExpiresAt - DateTime.UtcNow;
        if (remaining.TotalDays > 1)
        {
            return $"{(int)remaining.TotalDays} days";
        }
        if (remaining.TotalHours > 1)
        {
            return $"{(int)remaining.TotalHours} hours";
        }
        return "< 1 hour";
    }
}
