using Cronos;
using VulWall.Dashboard.Common.Services.ScanSchedule;

namespace VulWall.Dashboard.Tests.Common;

public class ScanCronGeneratorTests
{
    [Fact]
    public void RandomWeekly_ProducesParseableWeeklyCronInOffPeakWeekendWindow()
    {
        var rng = new Random(1234);
        for (var i = 0; i < 500; i++)
        {
            var cron = ScanCronGenerator.RandomWeekly(rng);

            // Must parse with the same library the dashboard uses to show the next scan.
            CronExpression.Parse(cron);

            var parts = cron.Split(' ');
            Assert.Equal(5, parts.Length);
            Assert.InRange(int.Parse(parts[0]), 0, 59);
            Assert.InRange(int.Parse(parts[1]), 0, 5);
            Assert.Equal("*", parts[2]);
            Assert.Equal("*", parts[3]);
            Assert.Contains(int.Parse(parts[4]), new[] { 0, 5, 6 });
        }
    }

    [Fact]
    public void RandomWeekly_WithoutSeed_StillReturnsValidCron()
    {
        var cron = ScanCronGenerator.RandomWeekly();

        Assert.NotNull(CronExpression.Parse(cron).GetNextOccurrence(DateTime.UtcNow, TimeZoneInfo.Utc));
    }
}
