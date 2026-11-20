using VulWall.Dashboard.Common.Services.Organization;
using OrgEntity = VulWall.Dashboard.Data.Entities.Organization.Organization;

namespace VulWall.Dashboard.Tests.Infrastructure;

internal sealed class FixedOrganizationContext(string orgId) : IOrganizationContext
{
    public Task<string> GetCurrentOrgIdAsync() => Task.FromResult(orgId);

    public Task<OrgEntity> GetCurrentOrganizationAsync() => Task.FromResult(new OrgEntity { Id = orgId });
}
