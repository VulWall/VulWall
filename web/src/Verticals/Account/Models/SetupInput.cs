using System.ComponentModel.DataAnnotations;

namespace VulWall.Dashboard.Account.Models;

public class SetupInput
{
    [Required(ErrorMessage = "Enter your email address.")]
    [EmailAddress(ErrorMessage = "Enter a valid email address.")]
    [StringLength(254)]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Choose a password.")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Repeat the password.")]
    [Compare(nameof(Password), ErrorMessage = "The passwords do not match.")]
    public string ConfirmPassword { get; set; } = string.Empty;

    [StringLength(100)]
    public string? OrganizationName { get; set; }

    /// <summary>First-run setup token from the startup log, carried in a hidden field.</summary>
    public string? Token { get; set; }
}
