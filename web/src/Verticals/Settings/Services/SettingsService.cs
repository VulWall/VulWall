using VulWall.Dashboard.Data.Entities.Organization;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Settings.Services;

public class SettingsService(OrganizationRepository organizationRepository)
{
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

    public async Task UpdateLogoAsync(string organizationId, byte[] logoBytes)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.Logo = logoBytes;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task RemoveLogoAsync(string organizationId)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.Logo = null;
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
