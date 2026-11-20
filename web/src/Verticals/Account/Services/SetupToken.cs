using System.Security.Cryptography;
using System.Text;

namespace VulWall.Dashboard.Account.Services;

/// <summary>
/// Secret that guards first-run /setup. Without it, anyone who reaches a fresh install before its
/// owner could create the admin account. SETUP_TOKEN sets it (install.sh writes a random one to
/// .env); without it, a token is generated per process and the startup log prints the setup link.
/// </summary>
public sealed class SetupToken
{
    public SetupToken(string? configured)
    {
        Value = string.IsNullOrWhiteSpace(configured)
            ? RandomNumberGenerator.GetHexString(32, lowercase: true)
            : configured.Trim();
    }

    public string Value { get; }

    public bool Matches(string? candidate) =>
        candidate != null
        && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(candidate), Encoding.UTF8.GetBytes(Value));
}
