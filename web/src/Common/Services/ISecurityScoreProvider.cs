using VulWall.Dashboard.Common.Models;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.Scan;

namespace VulWall.Dashboard.Common.Services;

public interface ISecurityScoreProvider
{
    /// <summary>
    /// Calculates security score using pre-fetched data to avoid redundant DB queries.
    /// </summary>
    Task<SecurityScoreResult> CalculateSecurityScoreAsync(
        List<Finding> allFindings,
        List<Discovery> allDiscoveries,
        List<Scan> recentDoneScans);
}
