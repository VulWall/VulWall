using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Scans.Models;
using VulWall.Dashboard.Scans.Services;

namespace VulWall.Dashboard.Tests.Scans;

public class ScanNowStateTests
{
    private static Scan S(ScanStatus status, double hoursAgo = 0.1) =>
        new() { Id = Guid.NewGuid().ToString(), Status = status, CreatedAt = DateTime.UtcNow.AddHours(-hoursAgo) };

    [Fact]
    public void NoScan_Allowed() =>
        Assert.Equal(ScanNowState.Allowed, ScansService.EvaluateScanNowState([S(ScanStatus.Done)]));

    [Fact]
    public void RunningScan_CanQueueAFollowUp() =>
        Assert.Equal(ScanNowState.InProgress, ScansService.EvaluateScanNowState([S(ScanStatus.Running)]));

    [Fact]
    public void RunningAndQueued_Queued() =>
        Assert.Equal(ScanNowState.Queued,
            ScansService.EvaluateScanNowState([S(ScanStatus.Queued), S(ScanStatus.Running)]));

    [Fact]
    public void StaleRunningScan_Allowed() =>
        Assert.Equal(ScanNowState.Allowed, ScansService.EvaluateScanNowState([S(ScanStatus.Running, 25)]));

    [Fact]
    public void LiveStatus_RunningWithQueuedFollowUp_ShowsBoth()
    {
        var model = ScansService.BuildLiveScanStatus([S(ScanStatus.Queued), S(ScanStatus.Running)], []);

        Assert.True(model.IsScanning);
        Assert.Equal(ScanNowState.Queued, model.ScanNowState);
        Assert.Contains(model.RecentRuns, r => r.Meta == "Queued");
    }
}
