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
    public void RunningScan_InProgress() =>
        Assert.Equal(ScanNowState.InProgress, ScansService.EvaluateScanNowState([S(ScanStatus.Running)]));

    [Fact]
    public void RunningAndQueued_Queued() =>
        Assert.Equal(ScanNowState.Queued,
            ScansService.EvaluateScanNowState([S(ScanStatus.Queued), S(ScanStatus.Running)]));

    [Fact]
    public void StaleRunningScan_Allowed() =>
        Assert.Equal(ScanNowState.Allowed, ScansService.EvaluateScanNowState([S(ScanStatus.Running, 25)]));

    [Fact]
    public void ScanQueuedLongAgoStartedRecently_InProgress()
    {
        var scan = S(ScanStatus.Running, 30);
        scan.StartedAt = DateTime.UtcNow.AddHours(-1);

        Assert.Equal(ScanNowState.InProgress, ScansService.EvaluateScanNowState([scan]));
    }

    [Fact]
    public void StartedMoreThan24hAgo_Allowed()
    {
        var scan = S(ScanStatus.Running, 30);
        scan.StartedAt = DateTime.UtcNow.AddHours(-25);

        Assert.Equal(ScanNowState.Allowed, ScansService.EvaluateScanNowState([scan]));
    }

    [Fact]
    public void LiveStatus_RunningWithQueuedFollowUp_ShowsBoth()
    {
        var model = ScansService.BuildLiveScanStatus([S(ScanStatus.Queued), S(ScanStatus.Running)], []);

        Assert.True(model.IsScanning);
        Assert.Equal(ScanNowState.Queued, model.ScanNowState);
        Assert.Contains(model.RecentRuns, r => r.Meta == "Queued");
    }

    [Theory]
    [InlineData(ScanType.Scheduled, "system", "scheduled")]
    [InlineData(ScanType.Requested, "admin@example.com", "manual · admin@example.com")]
    [InlineData(ScanType.Requested, "", "manual")]
    public void LiveStatus_TriggerLabel_FollowsScanType(ScanType type, string triggeredBy, string expected)
    {
        var scan = S(ScanStatus.Running);
        scan.Type = type;
        scan.TriggeredBy = triggeredBy;

        Assert.Equal(expected, ScansService.BuildLiveScanStatus([scan], []).Trigger);
    }
}
