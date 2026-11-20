using MongoDB.Driver;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.FindingSuppression;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Recommendations.Constants;
using VulWall.Dashboard.Recommendations.Models;

namespace VulWall.Dashboard.Recommendations.Services;

public class FindingSuppressionService(FindingSuppressionsRepository suppressionsRepository)
    : ISuppressionFilter
{
    /// <inheritdoc />
    public async Task<HashSet<(string DiscoveryId, string FindingType)>> GetActiveSuppressionKeysAsync()
    {
        var all = await suppressionsRepository.FindAsync(s => s.Active);
        return all
            .Select(s => (s.DiscoveryId, s.FindingType))
            .ToHashSet();
    }

    /// <inheritdoc />
    public IEnumerable<Finding> FilterSuppressed(
        IEnumerable<Finding> findings,
        HashSet<(string DiscoveryId, string FindingType)> suppressedKeys)
    {
        return findings.Where(f =>
            f.Status != "open" ||
            f.DiscoveryId == null ||
            f.FindingType == null ||
            !suppressedKeys.Contains((f.DiscoveryId, f.FindingType)));
    }

    /// <summary>
    /// Returns all active suppression records for the current org (for the Dismissed view).
    /// </summary>
    public async Task<List<FindingSuppression>> GetActiveSuppressionsAsync()
    {
        var all = await suppressionsRepository.FindAsync(s => s.Active);
        return all
            .OrderByDescending(s => s.SuppressedAt)
            .ToList();
    }

    /// <summary>
    /// Creates or updates a suppression for the given (discoveryId, findingType) pair.
    /// Idempotent: re-suppressing the same pair updates status/note rather than duplicating.
    /// On a duplicate-key race, treats the existing row as authoritative and updates it.
    /// </summary>
    public async Task SuppressAsync(
        string discoveryId,
        string findingType,
        string status,
        string suppressedBy,
        string? note)
    {
        var existing = (await suppressionsRepository.FindAsync(
            s => s.DiscoveryId == discoveryId && s.FindingType == findingType)).FirstOrDefault();

        if (existing != null)
        {
            existing.Status = status;
            existing.Note = note;
            existing.SuppressedBy = suppressedBy;
            existing.SuppressedAt = DateTime.UtcNow;
            existing.Active = true;
            await suppressionsRepository.UpdateAsync(existing);
        }
        else
        {
            var suppression = new FindingSuppression
            {
                DiscoveryId = discoveryId,
                FindingType = findingType,
                Status = status,
                Note = note,
                SuppressedBy = suppressedBy,
                SuppressedAt = DateTime.UtcNow,
                Active = true
            };

            try
            {
                await suppressionsRepository.CreateAsync(suppression);
            }
            catch (MongoWriteException ex) when (ex.WriteError.Category == ServerErrorCategory.DuplicateKey)
            {
                // A concurrent request already inserted this pair. Treat it as "already suppressed"
                // and update the existing record to reflect the latest intent.
                var race = (await suppressionsRepository.FindAsync(
                    s => s.DiscoveryId == discoveryId && s.FindingType == findingType)).FirstOrDefault();

                if (race != null)
                {
                    race.Status = status;
                    race.Note = note;
                    race.SuppressedBy = suppressedBy;
                    race.SuppressedAt = DateTime.UtcNow;
                    race.Active = true;
                    await suppressionsRepository.UpdateAsync(race);
                }
            }
        }
    }

    /// <summary>
    /// Deactivates a suppression (soft-delete to preserve audit history).
    /// </summary>
    public async Task UnsuppressAsync(string suppressionId)
    {
        var existing = await suppressionsRepository.GetByIdAsync(suppressionId);
        if (existing == null)
            return;

        existing.Active = false;
        await suppressionsRepository.UpdateAsync(existing);
    }

    /// <summary>
    /// Builds view models for the Dismissed/Accepted section, enriched with target information.
    /// </summary>
    public static List<DismissedFindingViewModel> BuildDismissedViewModels(
        List<FindingSuppression> suppressions,
        Dictionary<string, string?> discoveryTargets)
    {
        return suppressions.Select(s =>
        {
            discoveryTargets.TryGetValue(s.DiscoveryId, out var target);
            return new DismissedFindingViewModel
            {
                SuppressionId = s.Id,
                DiscoveryId = s.DiscoveryId,
                FindingType = s.FindingType,
                Status = s.Status,
                StatusLabel = s.Status == SuppressionStatus.FalsePositive ? "False positive" : "Accepted risk",
                Note = s.Note,
                SuppressedBy = s.SuppressedBy,
                SuppressedAt = s.SuppressedAt,
                Target = target ?? s.DiscoveryId
            };
        }).ToList();
    }
}
