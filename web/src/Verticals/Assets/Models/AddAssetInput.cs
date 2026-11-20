using System.ComponentModel.DataAnnotations;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Assets.Validation;

namespace VulWall.Dashboard.Assets.Models;

public class AddAssetInput
{
    [Required]
    public AssetType AssetType { get; set; }

    [RequiredIf(nameof(AssetType), AssetType.Domain, ErrorMessage = "Domain name is required")]
    public string? DomainName { get; set; }

    [RequiredIf(nameof(AssetType), AssetType.Ip, ErrorMessage = "IP address is required")]
    public string? IpAddress { get; set; }
}
