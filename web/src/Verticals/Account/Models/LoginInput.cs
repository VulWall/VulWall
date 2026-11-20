using System.ComponentModel.DataAnnotations;

namespace VulWall.Dashboard.Account.Models;

public class LoginInput
{
    [Required(ErrorMessage = "Enter your email address.")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Enter your password.")]
    public string Password { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}
