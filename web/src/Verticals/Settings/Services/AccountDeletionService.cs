using Microsoft.Extensions.Caching.Memory;
using VulWall.Dashboard.Common.Services.Auth0;
using VulWall.Dashboard.Common.Services.Email;
using VulWall.Dashboard.Data.Entities;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Settings.Services;

public class AccountDeletionService(
    IMemoryCache cache,
    IEmailService emailService,
    IAuth0ManagementService auth0ManagementService,
    StripePaymentService.StripePaymentService stripePaymentService,
    OrganizationRepository organizationRepository,
    AssetsRepository assetsRepository,
    ScansPublicRepository scansPublicRepository,
    FindingsPublicRepository findingsPublicRepository,
    DiscoveriesPublicRepository discoveriesPublicRepository,
    SharedLinksPublicRepository sharedLinksPublicRepository,
    AuditLogPublicRepository auditLogPublicRepository,
    DeletionLogRepository deletionLogRepository,
    ILogger<AccountDeletionService> logger)
{
    private static readonly TimeSpan OtpTtl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan OtpRequestCooldown = TimeSpan.FromSeconds(60);
    private const string OtpCacheKeyPrefix = "delete_account_otp_";
    private const string OtpAttemptsCacheKeyPrefix = "delete_account_otp_attempts_";
    private const string OtpRequestCooldownKeyPrefix = "delete_account_otp_cooldown_";
    private const int MaxOtpAttempts = 5;

    /// <summary>
    /// Generates a 6-digit OTP and sends it to the owner's email.
    /// The OTP is only written to cache after a successful email send to prevent
    /// brute-force against codes that were never delivered.
    /// Returns false if the template is not configured or the email send fails.
    /// </summary>
    public async Task<bool> SendDeletionOtpAsync(string orgId, string ownerEmail)
    {
        var otp = GenerateOtp();

        var variables = new Dictionary<string, object>
        {
            { "verificationCode", otp }
        };

        var sent = await emailService.SendTemplateAsync(ownerEmail, EmailTemplate.DeleteAccountVerification, variables);
        if (!sent)
        {
            logger.LogWarning("Failed to send deletion OTP email for org {OrgId}", orgId);
            return false;
        }

        // Write to cache only after confirmed delivery so no undelivered OTP sits in cache.
        // Also clear any stale attempt counter from a previous request.
        var cacheOptions = new MemoryCacheEntryOptions().SetAbsoluteExpiration(OtpTtl);
        cache.Set(BuildOtpCacheKey(orgId), otp, cacheOptions);
        cache.Remove(BuildAttemptsCacheKey(orgId));

        logger.LogInformation("Deletion OTP sent and cached for org {OrgId}", orgId);
        return true;
    }

    /// <summary>
    /// Validates the OTP and, if correct, executes the full account deletion sequence:
    /// 1. Cancel Stripe subscription (immediate)
    /// 2. Delete all org-scoped MongoDB data in parallel
    /// 3. Delete the Organization document
    /// 4. Delete the Auth0 user (failure here is logged as critical but does not throw)
    /// 5. Write a PII-free deletion log entry
    ///
    /// Returns true on success, false if the OTP is invalid, expired, or locked out.
    /// </summary>
    public async Task<bool> ConfirmAndDeleteAccountAsync(string orgId, string auth0UserId, string otp)
    {
        if (!ValidateOtp(orgId, otp))
        {
            logger.LogWarning("Invalid or expired deletion OTP for org {OrgId}", orgId);
            return false;
        }

        RemoveOtp(orgId);

        logger.LogInformation("Starting account deletion for org {OrgId}", orgId);

        await CancelStripeSubscriptionAsync(orgId);
        await DeleteOrgScopedDataAsync(orgId);
        await DeleteOrganizationAsync(orgId);
        await DeleteAuth0UserAsync(auth0UserId, orgId);
        await WriteDeletionLogAsync(orgId);

        logger.LogInformation("Account deletion complete for org {OrgId}", orgId);
        return true;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Returns true if the org has requested an OTP within the cooldown window
    /// and should be throttled to prevent Resend quota burn.
    /// </summary>
    public bool IsOtpRequestRateLimited(string orgId)
    {
        return cache.TryGetValue(BuildCooldownCacheKey(orgId), out _);
    }

    /// <summary>
    /// Records that an OTP was requested for this org, starting the cooldown window.
    /// </summary>
    public void RecordOtpRequest(string orgId)
    {
        cache.Set(BuildCooldownCacheKey(orgId), true, OtpRequestCooldown);
    }

    private static string BuildCooldownCacheKey(string orgId) => $"{OtpRequestCooldownKeyPrefix}{orgId}";

    private static string GenerateOtp()
    {
        return Random.Shared.Next(100_000, 999_999).ToString();
    }

    private static string BuildOtpCacheKey(string orgId) => $"{OtpCacheKeyPrefix}{orgId}";

    private static string BuildAttemptsCacheKey(string orgId) => $"{OtpAttemptsCacheKeyPrefix}{orgId}";

    /// <summary>
    /// Validates the submitted OTP against the cached value for the given org.
    /// Tracks failed attempts and invalidates the OTP after MaxOtpAttempts failures
    /// to prevent brute-force within the 10-minute window.
    /// </summary>
    private bool ValidateOtp(string orgId, string submittedOtp)
    {
        if (!cache.TryGetValue(BuildOtpCacheKey(orgId), out string? storedOtp)
            || string.IsNullOrEmpty(storedOtp))
        {
            return false;
        }

        if (storedOtp == submittedOtp)
        {
            return true;
        }

        // Increment failed attempt counter. Expires at the same TTL as the OTP.
        var attemptsKey = BuildAttemptsCacheKey(orgId);
        var attempts = cache.GetOrCreate(attemptsKey, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = OtpTtl;
            return 0;
        });

        attempts++;
        cache.Set(attemptsKey, attempts, OtpTtl);

        if (attempts >= MaxOtpAttempts)
        {
            // Invalidate the OTP so the user must request a fresh code.
            cache.Remove(BuildOtpCacheKey(orgId));
            cache.Remove(attemptsKey);
            logger.LogWarning(
                "Deletion OTP for org {OrgId} invalidated after {MaxAttempts} failed attempts",
                orgId, MaxOtpAttempts);
        }

        return false;
    }

    private void RemoveOtp(string orgId)
    {
        cache.Remove(BuildOtpCacheKey(orgId));
        cache.Remove(BuildAttemptsCacheKey(orgId));
    }

    private async Task CancelStripeSubscriptionAsync(string orgId)
    {
        try
        {
            var organizations = await organizationRepository.FindAsync(o => o.Id == orgId);
            var org = organizations.FirstOrDefault();
            var subscriptionId = org?.Plan?.StripeSubscriptionId;

            if (string.IsNullOrEmpty(subscriptionId))
            {
                logger.LogInformation("No active Stripe subscription for org {OrgId} — skipping cancellation", orgId);
                return;
            }

            await stripePaymentService.CancelSubscriptionAsync(subscriptionId, cancelNow: true);
            logger.LogInformation("Cancelled Stripe subscription {SubscriptionId} for org {OrgId}", subscriptionId, orgId);
        }
        catch (Exception ex)
        {
            // Stripe failure should not block deletion — org data is about to be purged anyway.
            logger.LogError(ex, "Failed to cancel Stripe subscription for org {OrgId}", orgId);
        }
    }

    private async Task DeleteOrgScopedDataAsync(string orgId)
    {
        // Delete all org-scoped collections in parallel for efficiency.
        var deletionTasks = new[]
        {
            DeleteCollectionAsync("assets",      () => assetsRepository.DeleteManyAsync(e => e.OrgId == orgId)),
            DeleteCollectionAsync("scans",       () => scansPublicRepository.DeleteManyAsync(e => e.OrgId == orgId)),
            DeleteCollectionAsync("findings",    () => findingsPublicRepository.DeleteManyAsync(e => e.OrgId == orgId)),
            DeleteCollectionAsync("discoveries", () => discoveriesPublicRepository.DeleteManyAsync(e => e.OrgId == orgId)),
            DeleteCollectionAsync("shared_links",() => sharedLinksPublicRepository.DeleteManyAsync(e => e.OrgId == orgId)),
            DeleteCollectionAsync("audit_logs",  () => auditLogPublicRepository.DeleteManyAsync(e => e.OrgId == orgId)),
        };

        await Task.WhenAll(deletionTasks);
    }

    private async Task DeleteCollectionAsync(string collectionName, Func<Task<long>> deleteAction)
    {
        try
        {
            var count = await deleteAction();
            logger.LogInformation("Deleted {Count} documents from {Collection} for org during account deletion", count, collectionName);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to delete {Collection} data during account deletion", collectionName);
            throw;
        }
    }

    private async Task DeleteOrganizationAsync(string orgId)
    {
        try
        {
            await organizationRepository.DeleteAsync(orgId);
            logger.LogInformation("Deleted organization document for org {OrgId}", orgId);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to delete organization document for org {OrgId}", orgId);
            throw;
        }
    }

    private async Task DeleteAuth0UserAsync(string auth0UserId, string orgId)
    {
        // Auth0 deletion runs last. If it fails the user's data is already gone, so we log
        // as critical (operations team must manually delete the Auth0 account) but do not
        // re-throw — the deletion flow must still sign the user out cleanly.
        try
        {
            await auth0ManagementService.DeleteUserAsync(auth0UserId);
            logger.LogInformation("Deleted Auth0 user {UserId} for org {OrgId}", auth0UserId, orgId);
        }
        catch (Exception ex)
        {
            logger.LogCritical(
                ex,
                "CRITICAL: Failed to delete Auth0 user {UserId} for org {OrgId} after all data was purged. " +
                "Manual intervention required to remove the Auth0 account.",
                auth0UserId,
                orgId);
        }
    }

    private async Task WriteDeletionLogAsync(string orgId)
    {
        try
        {
            await deletionLogRepository.CreateAsync(new DeletionLog
            {
                OrgId = orgId,
                DeletedAt = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            // Non-blocking — the account deletion was successful even if the log write fails.
            logger.LogError(ex, "Failed to write deletion log for org {OrgId}", orgId);
        }
    }
}
