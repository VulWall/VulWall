using System.Runtime.CompilerServices;

namespace VulWall.Dashboard.Tests;

/// <summary>
/// ServiceSettings is a process-wide lazy singleton loaded from environment variables and it
/// throws when required variables are missing. Set the values once, before any test runs,
/// so tests that touch ServiceSettings do not depend on execution order.
/// </summary>
internal static class TestEnvironment
{
    public const string NightWatchBaseUrl = "http://nightwatch.test";

    [ModuleInitializer]
    internal static void Initialize()
    {
        SetIfMissing("AUTH0_DOMAIN", "auth.example.test");
        SetIfMissing("AUTH0_MANAGEMENT_DOMAIN", "auth.example.test");
        SetIfMissing("AUTH0_CLIENTID", "test-client");
        SetIfMissing("AUTH0_CLIENTSECRET", "test-secret");
        Environment.SetEnvironmentVariable("NIGHTWATCH_BASE_URL", NightWatchBaseUrl);
    }

    private static void SetIfMissing(string name, string value)
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name)))
            Environment.SetEnvironmentVariable(name, value);
    }
}
