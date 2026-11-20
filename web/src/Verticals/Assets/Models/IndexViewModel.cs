namespace VulWall.Dashboard.Assets.Models;

public class IndexViewModel
{
    public List<AssetItemViewModel> Assets { get; set; } = new();
    public int TotalAssets { get; set; }
    public int ActiveAssets { get; set; }
    public int InactiveAssets { get; set; }
    public int PendingAssets { get; set; }
}
