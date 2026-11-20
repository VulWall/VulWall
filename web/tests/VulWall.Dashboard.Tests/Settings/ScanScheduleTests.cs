using Cronos;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Entities.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings.Models;
using VulWall.Dashboard.Settings.Services;
using VulWall.Dashboard.Tests.Infrastructure;

namespace VulWall.Dashboard.Tests.Settings;

public class ScanScheduleCronTests
{
    // Winter and summer instants, so DST zones have a known offset.
    private static readonly DateTime Winter = new(2026, 1, 15, 12, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime Summer = new(2026, 7, 15, 12, 0, 0, DateTimeKind.Utc);

    private static string BuildCron(ScanScheduleInput input, DateTime now)
    {
        var (settings, error) = ScanScheduleCron.Build(input, null, now);
        Assert.Null(error);
        Assert.NotNull(settings);
        Assert.True(settings.Enabled);
        Assert.Equal(input.TimeZone, settings.TimeZone);
        CronExpression.Parse(settings.ScanCron!); // the dashboard parses it with Cronos too
        return settings.ScanCron!;
    }

    public static TheoryData<ScanScheduleInput, string, string> Schedules => new()
    {
        // UTC: no shift
        { new() { Frequency = ScanFrequency.Daily, Time = "02:30" }, "winter", "30 2 * * *" },
        { new() { Frequency = ScanFrequency.Weekly, DayOfWeek = DayOfWeek.Saturday, Time = "03:37" }, "winter", "37 3 * * 6" },
        { new() { Frequency = ScanFrequency.Monthly, DayOfMonth = 15, Time = "22:45" }, "winter", "45 22 15 * *" },
        { new() { Frequency = ScanFrequency.Weekly, DayOfWeek = DayOfWeek.Sunday, Time = "00:00" }, "winter", "0 0 * * 0" },
        // Europe/Amsterdam: UTC+1 in winter, UTC+2 in summer
        { new() { Frequency = ScanFrequency.Daily, Time = "04:00", TimeZone = "Europe/Amsterdam" }, "winter", "0 3 * * *" },
        { new() { Frequency = ScanFrequency.Daily, Time = "04:00", TimeZone = "Europe/Amsterdam" }, "summer", "0 2 * * *" },
        // Weekday wraps back: Monday 00:30 local is Sunday 23:30 UTC
        { new() { Frequency = ScanFrequency.Weekly, DayOfWeek = DayOfWeek.Monday, Time = "00:30", TimeZone = "Europe/Amsterdam" }, "winter", "30 23 * * 0" },
        // Weekday wraps forward: Saturday 23:00 New York (UTC-5) is Sunday 04:00 UTC
        { new() { Frequency = ScanFrequency.Weekly, DayOfWeek = DayOfWeek.Saturday, Time = "23:00", TimeZone = "America/New_York" }, "winter", "0 4 * * 0" },
        // Half-hour offset: Kolkata is UTC+5:30
        { new() { Frequency = ScanFrequency.Weekly, DayOfWeek = DayOfWeek.Monday, Time = "05:00", TimeZone = "Asia/Kolkata" }, "winter", "30 23 * * 0" },
        { new() { Frequency = ScanFrequency.Daily, Time = "12:15", TimeZone = "Asia/Kolkata" }, "winter", "45 6 * * *" },
        // Month day shifts inside 1..28
        { new() { Frequency = ScanFrequency.Monthly, DayOfMonth = 10, Time = "00:30", TimeZone = "Europe/Amsterdam" }, "winter", "30 23 9 * *" },
        { new() { Frequency = ScanFrequency.Monthly, DayOfMonth = 27, Time = "22:00", TimeZone = "America/New_York" }, "winter", "0 3 28 * *" },
    };

    [Theory]
    [MemberData(nameof(Schedules))]
    public void Build_ConvertsLocalScheduleToUtcCron(ScanScheduleInput input, string season, string expected)
    {
        var now = season == "summer" ? Summer : Winter;
        Assert.Equal(expected, BuildCron(input, now));
    }

    [Theory]
    [MemberData(nameof(Schedules))]
    public void ToInput_RoundTripsWhatBuildWrote(ScanScheduleInput input, string season, string _)
    {
        var now = season == "summer" ? Summer : Winter;
        var (settings, _) = ScanScheduleCron.Build(input, null, now);

        var (back, isCustom) = ScanScheduleCron.ToInput(settings, now);

        Assert.False(isCustom);
        Assert.Equal(input.Frequency, back.Frequency);
        Assert.Equal(input.Time, back.Time);
        Assert.Equal(input.TimeZone, back.TimeZone);
        if (input.Frequency == ScanFrequency.Weekly) Assert.Equal(input.DayOfWeek, back.DayOfWeek);
        if (input.Frequency == ScanFrequency.Monthly) Assert.Equal(input.DayOfMonth, back.DayOfMonth);
    }

    [Theory]
    [InlineData(1, "00:30", "Europe/Amsterdam")]  // day 0 in UTC (previous month)
    [InlineData(28, "22:00", "America/New_York")] // day 29 in UTC (missing in February)
    public void Build_Monthly_RejectsDayThatLeavesOneTo28InUtc(int day, string time, string zone)
    {
        var (settings, error) = ScanScheduleCron.Build(
            new ScanScheduleInput { Frequency = ScanFrequency.Monthly, DayOfMonth = day, Time = time, TimeZone = zone }, null, Winter);

        Assert.Null(settings);
        Assert.Contains("Choose a day from 2 to 27", error);
    }

    public static TheoryData<ScanScheduleInput> InvalidInputs => new()
    {
        new() { Frequency = (ScanFrequency)99 },
        new() { Frequency = ScanFrequency.Daily, Time = "25:00" },
        new() { Frequency = ScanFrequency.Daily, Time = "2am" },
        new() { Frequency = ScanFrequency.Daily, Time = "" },
        new() { Frequency = ScanFrequency.Daily, TimeZone = "Mars/Olympus_Mons" },
        new() { Frequency = ScanFrequency.Daily, TimeZone = "" },
        new() { Frequency = ScanFrequency.Weekly, DayOfWeek = (DayOfWeek)7 },
        new() { Frequency = ScanFrequency.Monthly, DayOfMonth = 0 },
        new() { Frequency = ScanFrequency.Monthly, DayOfMonth = 29 },
        new() { Frequency = ScanFrequency.Off, TimeZone = "not/a-zone" },
    };

    [Theory]
    [MemberData(nameof(InvalidInputs))]
    public void Build_RejectsInvalidInput(ScanScheduleInput input)
    {
        var (settings, error) = ScanScheduleCron.Build(input, null, Winter);

        Assert.Null(settings);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public void Build_Off_DisablesAndKeepsTheCron()
    {
        var current = new ScanSettings { ScanCron = "37 3 * * 6", Enabled = true };

        var (settings, error) = ScanScheduleCron.Build(
            new ScanScheduleInput { Frequency = ScanFrequency.Off, TimeZone = "Europe/Amsterdam" }, current, Winter);

        Assert.Null(error);
        Assert.False(settings!.Enabled);
        Assert.Equal("37 3 * * 6", settings.ScanCron);
        Assert.Null(settings.ActiveCron);
    }

    [Fact]
    public void ToInput_Disabled_ShowsOffButKeepsTheDayAndTime()
    {
        var (input, isCustom) = ScanScheduleCron.ToInput(
            new ScanSettings { ScanCron = "37 3 * * 5", Enabled = false }, Winter);

        Assert.False(isCustom);
        Assert.Equal(ScanFrequency.Off, input.Frequency);
        Assert.Equal(DayOfWeek.Friday, input.DayOfWeek);
        Assert.Equal("03:37", input.Time);
        Assert.Equal("UTC", input.TimeZone);
    }

    [Theory]
    [InlineData("*/15 * * * *")]
    [InlineData("0 2 * * 1-5")]
    [InlineData("0 2 1 1 *")]
    [InlineData("0 2 31 * *")]
    [InlineData("garbage")]
    public void ToInput_CronTheFormCannotShow_IsCustom(string cron)
    {
        var (input, isCustom) = ScanScheduleCron.ToInput(new ScanSettings { ScanCron = cron }, Winter);

        Assert.True(isCustom);
        Assert.Equal(ScanFrequency.Weekly, input.Frequency);
    }

    [Fact]
    public void ToInput_NoSchedule_IsOff()
    {
        var (input, isCustom) = ScanScheduleCron.ToInput(null, Winter);

        Assert.False(isCustom);
        Assert.Equal(ScanFrequency.Off, input.Frequency);
    }

    [Fact]
    public void ToInput_GeneratedDefault_IsWeeklyUtc()
    {
        var cron = VulWall.Dashboard.Common.Services.ScanSchedule.ScanCronGenerator.RandomWeekly(new Random(7));

        var (input, isCustom) = ScanScheduleCron.ToInput(new ScanSettings { ScanCron = cron }, Winter);

        Assert.False(isCustom);
        Assert.Equal(ScanFrequency.Weekly, input.Frequency);
        Assert.Equal(cron, BuildCron(input, Winter));
    }

    [Fact]
    public void BuildScanSchedule_Disabled_HasNoNextScan()
    {
        var vm = SettingsService.BuildScanSchedule(new ScanSettings { ScanCron = "0 2 * * *", Enabled = false }, Winter);

        Assert.Null(vm.NextScanUtc);
        Assert.Equal(ScanFrequency.Off, vm.Input.Frequency);
    }

    [Fact]
    public void BuildScanSchedule_Enabled_ShowsNextScanInTheChosenZone()
    {
        var vm = SettingsService.BuildScanSchedule(
            new ScanSettings { ScanCron = "0 3 * * *", Enabled = true, TimeZone = "Europe/Amsterdam" }, Winter);

        Assert.NotNull(vm.NextScanUtc);
        Assert.Equal(3, vm.NextScanUtc.Value.Hour);
        // NextScanCalculator reads the real clock, so compare with the zone's offset at that run.
        var amsterdam = TimeZoneInfo.FindSystemTimeZoneById("Europe/Amsterdam");
        Assert.Equal(TimeZoneInfo.ConvertTimeFromUtc(vm.NextScanUtc.Value, amsterdam), vm.NextScanLocal);
        Assert.True(vm.ZoneHasDaylightSaving);
        Assert.Equal("UTC", vm.TimeZones[0].Id);
    }

    [Fact]
    public void ActiveCron_IsNullWhenDisabledOrEmpty()
    {
        Assert.Equal("0 2 * * *", new ScanSettings { ScanCron = "0 2 * * *" }.ActiveCron);
        Assert.Null(new ScanSettings { ScanCron = "0 2 * * *", Enabled = false }.ActiveCron);
        Assert.Null(new ScanSettings { ScanCron = " " }.ActiveCron);
    }
}

[Collection(MongoCollection.Name)]
public class ScanScheduleStorageTests(MongoFixture mongo)
{
    [Fact]
    public async Task UpdateScanSchedule_StoresUtcCronAndEnabledUnderScanSettings()
    {
        var db = mongo.NewDatabase();
        var repo = new OrganizationRepository(db);
        var org = await DefaultOrganization.EnsureExistsAsync(repo);
        var service = new SettingsService(repo);

        var error = await service.UpdateScanScheduleAsync(org.Id, new ScanScheduleInput
        {
            Frequency = ScanFrequency.Weekly, DayOfWeek = DayOfWeek.Wednesday, Time = "01:15", TimeZone = "UTC"
        });

        Assert.Null(error);
        var doc = await db.GetCollection<BsonDocument>("organizations").Find(FilterDefinition<BsonDocument>.Empty).SingleAsync();
        var stored = doc["scan_settings"].AsBsonDocument;
        Assert.Equal("15 1 * * 3", stored["scan_cron"].AsString);
        Assert.True(stored["enabled"].AsBoolean);
    }

    [Fact]
    public async Task UpdateScanSchedule_Off_WritesEnabledFalse()
    {
        var db = mongo.NewDatabase();
        var repo = new OrganizationRepository(db);
        var org = await DefaultOrganization.EnsureExistsAsync(repo);
        var originalCron = org.ScanSettings!.ScanCron;

        var error = await new SettingsService(repo).UpdateScanScheduleAsync(org.Id, new ScanScheduleInput { Frequency = ScanFrequency.Off });

        Assert.Null(error);
        var stored = (await repo.GetByIdAsync(org.Id))!.ScanSettings!;
        Assert.False(stored.Enabled);
        Assert.Equal(originalCron, stored.ScanCron);
    }

    [Fact]
    public async Task UpdateScanSchedule_InvalidInput_SavesNothing()
    {
        var db = mongo.NewDatabase();
        var repo = new OrganizationRepository(db);
        var org = await DefaultOrganization.EnsureExistsAsync(repo);

        var error = await new SettingsService(repo).UpdateScanScheduleAsync(org.Id, new ScanScheduleInput
        {
            Frequency = ScanFrequency.Daily, Time = "99:99"
        });

        Assert.NotNull(error);
        var stored = (await repo.GetByIdAsync(org.Id))!.ScanSettings!;
        Assert.Equal(org.ScanSettings!.ScanCron, stored.ScanCron);
        Assert.True(stored.Enabled);
    }

    [Fact]
    public async Task DefaultOrganization_WritesEnabledExplicitly()
    {
        // The scanner decodes a missing "enabled" as on, but write it so both sides agree on sight.
        var db = mongo.NewDatabase();
        await DefaultOrganization.EnsureExistsAsync(new OrganizationRepository(db));

        var doc = await db.GetCollection<BsonDocument>("organizations").Find(FilterDefinition<BsonDocument>.Empty).SingleAsync();
        Assert.True(doc["scan_settings"]["enabled"].AsBoolean);
    }
}
