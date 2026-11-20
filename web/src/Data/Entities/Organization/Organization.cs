using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Organization;

/// <summary>
/// Organization entity - represents a company/organization.
/// A self-hosted install has a single organization, created at startup.
/// The organization's _id is used as the org_id for scoping other entities.
/// </summary>
[BsonIgnoreExtraElements]
public class Organization : IEntity<string>
{
    [BsonId]
    [BsonElement("_id")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();

    /// <summary>
    /// Company name (initially empty, filled in settings)
    /// </summary>
    [BsonElement("company_name")]
    public string? CompanyName { get; set; }

    /// <summary>
    /// Industry (initially empty, filled in settings)
    /// </summary>
    [BsonElement("industry")]
    public string? Industry { get; set; }

    /// <summary>
    /// Company website (initially empty, filled in settings)
    /// </summary>
    [BsonElement("website")]
    public string? Website { get; set; }

    /// <summary>
    /// Company logo stored as binary data (max 500KB, max dimensions 250x250)
    /// </summary>
    [BsonElement("logo")]
    public byte[]? Logo { get; set; }

    /// <summary>
    /// Email address of the admin, set during first-run setup.
    /// </summary>
    [BsonElement("owner_email")]
    public string? OwnerEmail { get; set; }

    /// <summary>
    /// UTC timestamp when the organization was created
    /// </summary>
    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// UTC timestamp when the organization was last updated
    /// </summary>
    [BsonElement("updated_at")]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Scan schedule (read by the scanner's scan coordinator)
    /// </summary>
    [BsonElement("subscription_settings")]
    public SubscriptionSettings? SubscriptionSettings { get; set; }

    /// <summary>
    /// Whether the onboarding tour has been completed by the organization
    /// </summary>
    [BsonElement("tour_completed")]
    public bool TourCompleted { get; set; }

    /// <summary>
    /// API keys for public API access. Each key resolves to this organization.
    /// </summary>
    [BsonElement("api_keys")]
    public List<ApiKey>? ApiKeys { get; set; }
}