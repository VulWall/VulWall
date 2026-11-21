using System.Runtime.CompilerServices;

namespace VulWall.Dashboard.Tests.Common;

/// <summary>
/// The sidebar shows the organization, the admin email and the update badge ("this install is outdated").
/// Anonymous pages use the same layout (the error pages), so the layout must render it for signed-in users only.
/// </summary>
public sealed class LayoutSidebarTests
{
    [Fact]
    public void Sidebar_IsRenderedOnlyForSignedInUsers()
    {
        var lines = File.ReadAllLines(Path.Combine(SourceRoot(), "Common", "Views", "_Layout.cshtml"));
        var sidebar = Array.FindIndex(lines, l => l.Contains("PartialAsync(\"_Sidebar\")"));
        Assert.True(sidebar > 0, "_Layout.cshtml no longer renders _Sidebar: update this test");

        // Walk up to the block that encloses the partial and check its condition.
        var depth = 0;
        for (var i = sidebar - 1; i >= 0; i--)
        {
            depth += lines[i].Count(c => c == '}') - lines[i].Count(c => c == '{');
            if (depth >= 0)
                continue;
            var condition = lines[i].Contains("@if") ? lines[i] : lines[i - 1];
            Assert.Contains("@if (User.Identity?.IsAuthenticated == true)", condition);
            return;
        }
        Assert.Fail("_Sidebar is rendered outside an authenticated-only block");
    }

    private static string SourceRoot([CallerFilePath] string thisFile = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(thisFile)!, "..", "..", "..", "src"));
}
