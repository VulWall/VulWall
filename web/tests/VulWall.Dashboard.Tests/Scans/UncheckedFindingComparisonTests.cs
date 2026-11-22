using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Scans.Services;

namespace VulWall.Dashboard.Tests.Scans;

/// <summary>
/// s2 could not fully check asset A (degraded): the scanner left f-a open and listed it in s2's
/// unchecked_finding_ids. s3 sees it again. A comparison must not call it added in s3.
/// </summary>
public class UncheckedFindingComparisonTests
{
    private const string AssetA = "asset-a";
    private static readonly DateTime S1At = DateTime.UtcNow.AddHours(-3);

    [Fact]
    public void UncheckedFinding_IsNotAdded_WhenTheNextScanSeesItAgain()
    {
        var s2 = NewScan("s2", S1At.AddHours(1));
        s2.UncheckedFindingIds = ["f-a"];
        var s3 = NewScan("s3", S1At.AddHours(2));
        var finding = new Finding
        {
            Id = "f-a", OrgId = "org-1", DiscoveryId = "d-a", ScanIds = ["s1", "s3"],
            Severity = Severity.High, Title = "A open", FindingType = "type-a", Source = "nuclei",
            FirstDetected = S1At, LastDetected = S1At,
        };

        var cmp = ScansService.BuildComparison(s2, s3, [finding], id => id == "d-a" ? [AssetA] : null);

        Assert.Empty(cmp.Added);
        Assert.Equal(0, cmp.AddedTotal);
    }

    private static Scan NewScan(string id, DateTime at) => new()
    {
        Id = id,
        OrgId = "org-1",
        Status = ScanStatus.Done,
        CreatedAt = at,
        StartedAt = at,
        TargetedAssets = [new TargetedAsset { AssetId = AssetA, Type = "domain", Value = "a.com" }],
    };
}
