using VulWall.Dashboard.Common.Services.ScanSchedule;
using VulWall.Dashboard.Data.Entities.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings.Models;

namespace VulWall.Dashboard.Settings.Services;

public class SettingsService(OrganizationRepository organizationRepository)
{
    private static readonly Lazy<IReadOnlyList<TimeZoneOption>> TimeZoneOptions = new(() =>
    {
        // Sorted by base UTC offset; UTC first so the default is at the top.
        var zones = TimeZoneInfo.GetSystemTimeZones()
            .Where(z => z.Id != TimeZoneInfo.Utc.Id)
            .Select(z => new TimeZoneOption(z.Id, z.DisplayName));
        return [new TimeZoneOption(TimeZoneInfo.Utc.Id, "(UTC) Coordinated Universal Time"), .. zones];
    });

    public static ScanScheduleViewModel BuildScanSchedule(ScanSettings? settings, DateTime nowUtc)
    {
        var (input, isCustom) = ScanScheduleCron.ToInput(settings, nowUtc);
        ScanScheduleCron.TryFindTimeZone(input.TimeZone, out var zone);
        var next = NextScanCalculator.Compute(settings?.ActiveCron)?.NextUtc;

        return new ScanScheduleViewModel
        {
            Input = input,
            Cron = settings?.ScanCron,
            IsCustom = isCustom,
            NextScanUtc = next,
            NextScanLocal = next is { } utc ? TimeZoneInfo.ConvertTimeFromUtc(utc, zone) : null,
            ZoneHasDaylightSaving = zone.SupportsDaylightSavingTime,
            TimeZones = TimeZoneOptions.Value
        };
    }

    /// <summary>Saves the schedule, or returns an error message and saves nothing.</summary>
    public async Task<string?> UpdateScanScheduleAsync(string organizationId, ScanScheduleInput input)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        var (settings, error) = ScanScheduleCron.Build(input, organization.ScanSettings, DateTime.UtcNow);
        if (settings == null)
            return error;

        organization.ScanSettings = settings;
        organization.UpdatedAt = DateTime.UtcNow;
        await organizationRepository.UpdateAsync(organization);
        return null;
    }

    public async Task UpdateCompanyInfoAsync(string organizationId, string? companyName, string? industry, string? website)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.CompanyName = companyName;
        organization.Industry = industry;
        organization.Website = website;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task UpdateLogoAsync(string organizationId, byte[] logoBytes, string contentType)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.Logo = logoBytes;
        organization.LogoContentType = contentType;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task RemoveLogoAsync(string organizationId)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.Logo = null;
        organization.LogoContentType = null;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task MarkTourCompletedAsync(string organizationId)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.TourCompleted = true;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task ResetTourAsync(string organizationId)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.TourCompleted = false;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }
}
