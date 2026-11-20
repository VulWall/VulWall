using VulWall.Dashboard.Attributes;

namespace VulWall.Dashboard.Common.Utils;

public class ServiceSettings : EnvLoader
{
    private static readonly Lazy<ServiceSettings> ServiceInstance = new(() => new ServiceSettings());
    public static ServiceSettings Instance => ServiceInstance.Value;

    [Env(Name = "PORT", Default = "8080")]
    public int Port;

    [Env(Name = "MONGO_URI", Default = "mongodb://localhost:27017")]
    public string Mongo_URI;

    /// <summary>
    /// Database name. Kept separate from MONGO_URI so the same URI works for the scanner and the web app.
    /// </summary>
    [Env(Name = "MONGO_DB", Default = "vulwall")]
    public string MongoDb = "vulwall";

    [Env(Name = "ANTHROPIC_API_KEY", Required = false)]
    public string AnthropicApiKey = string.Empty;

    [Env(Name = "DEFAULT_AI_MODEL", Default = "claude-sonnet-4-6")]
    public string DefaultAIModel = string.Empty;

    /// <summary>
    /// Comma-separated IPs/CIDR ranges of reverse proxies whose X-Forwarded-* headers are trusted.
    /// Empty means only loopback is trusted.
    /// </summary>
    [Env(Name = "TRUSTED_PROXIES", Required = false)]
    public string TrustedProxies = string.Empty;

    /// <summary>
    /// Enables password-protected shared report links. When false (default) the share UI is
    /// hidden and /shared-reports/* returns 404.
    /// </summary>
    [Env(Name = "SHARED_LINKS_ENABLED", Default = "false")]
    public bool SharedLinksEnabled;

    /// <summary>
    /// Set to true when the app is served over HTTPS (directly or behind a TLS-terminating proxy).
    /// Enables Secure cookies, HSTS and HTTP→HTTPS redirection. Default false so a plain
    /// <c>docker compose up</c> on http://localhost works.
    /// </summary>
    [Env(Name = "SECURE_COOKIES", Default = "false")]
    public bool SecureCookies;

    /// <summary>
    /// Directory for ASP.NET Core data-protection keys. The image sets /data/keys (a web-only
    /// volume). Empty uses the ASP.NET Core default for the current user.
    /// </summary>
    [Env(Name = "DATA_PROTECTION_KEYS_DIR", Required = false)]
    public string DataProtectionKeysDir = string.Empty;

    /// <summary>
    /// Fixed first-run setup token. install.sh puts a random one in .env. Empty generates a
    /// random token at startup and logs the setup link.
    /// </summary>
    [Env(Name = "SETUP_TOKEN", Required = false)]
    public string SetupToken = string.Empty;
}
