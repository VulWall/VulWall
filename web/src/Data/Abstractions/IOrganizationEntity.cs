namespace VulWall.Dashboard.Data.Abstractions;

/// <summary>
/// Marker interface for entities that belong to an organization.
/// Ensures organization-based data isolation.
/// </summary>
public interface IOrganizationEntity
{
    /// <summary>
    /// The organization ID that owns this entity
    /// </summary>
    string OrgId { get; set; }
}
