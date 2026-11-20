using System.ComponentModel.DataAnnotations;

namespace VulWall.Dashboard.Account.Models;

public class ChangePasswordInput
{
    [Required(ErrorMessage = "Enter your current password.")]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Choose a new password.")]
    public string NewPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Repeat the new password.")]
    [Compare(nameof(NewPassword), ErrorMessage = "The new passwords do not match.")]
    public string ConfirmNewPassword { get; set; } = string.Empty;
}
