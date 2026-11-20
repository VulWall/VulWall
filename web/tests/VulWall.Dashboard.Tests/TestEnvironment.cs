using System.Runtime.CompilerServices;

namespace VulWall.Dashboard.Tests;

/// <summary>
/// ServiceSettings is a process-wide lazy singleton loaded from environment variables.
/// Set test values once, before any test runs, so tests that touch ServiceSettings do not
/// depend on execution order.
/// </summary>
internal static class TestEnvironment
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        Environment.SetEnvironmentVariable("ANTHROPIC_API_KEY", "");
    }
}
