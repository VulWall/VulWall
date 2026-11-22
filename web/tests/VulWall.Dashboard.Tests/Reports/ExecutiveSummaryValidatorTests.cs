using VulWall.Dashboard.Reports.Services.ReportGeneration;

namespace VulWall.Dashboard.Tests.Reports;

public class ExecutiveSummaryValidatorTests
{
    [Theory]
    [InlineData("Your perimeter looks healthy, with no urgent exposure found. A few minor settings are worth tidying up.")]
    [InlineData("Several services run outdated software, e.g. the mail server, that attackers could use to read customer data. Patch version 7.5 first.")]
    [InlineData("Your public services have two serious weaknesses that could expose customer data. Fix the login page first. Then review the server settings.")]
    public void Validate_AcceptsPlainSummary(string summary) =>
        Assert.Null(ExecutiveSummaryValidator.Validate(summary));

    [Theory]
    [InlineData(null, "too short")]
    [InlineData("All good.", "too short")]
    [InlineData("""{"summary": "Your perimeter looks healthy, with no urgent exposure found in this scan."}""", "JSON")]
    [InlineData("## Summary\nYour perimeter looks healthy, with no urgent exposure found in this scan today.", "Markdown")]
    [InlineData("- Your perimeter looks healthy.\n- No urgent exposure was found in this scan today at all.", "Markdown")]
    [InlineData("Your perimeter is **healthy**, with no urgent exposure found in this scan today, overall.", "Markdown")]
    [InlineData("One issue. Two issues. Three issues. Four issues. Five issues. Six issues. Seven issues here.", "sentences")]
    public void Validate_RejectsUnusableSummary(string? summary, string reason) =>
        Assert.Contains(reason, ExecutiveSummaryValidator.Validate(summary));

    [Fact]
    public void Validate_RejectsTooLong() =>
        Assert.Contains("too long", ExecutiveSummaryValidator.Validate(new string('a', 1300) + "."));
}
