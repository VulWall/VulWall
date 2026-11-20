namespace VulWall.Dashboard.Settings.Models;

public sealed record ConfirmDeletionRequest
{
    public string? Otp { get; init; }
}
