using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Organization;

/// <summary>
/// Organization entity - represents a company/organization.
/// Users (Auth0 IDs) are stored in the user_ids array.
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
    /// Array of Auth0 User IDs belonging to this organization (e.g., ["auth0|123456789", "auth0|987654321"])
    /// </summary>
    [BsonElement("user_ids")]
    public List<string> UserIds { get; set; } = new();

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
    /// Certificate visibility status - organization-level setting applied to all users
    /// </summary>
    [BsonElement("cert_visible")]
    public bool CertVisible { get; set; } = true;
    
    /// <summary>
    /// Whether this organization has been claimed by a user.
    /// Legacy unclaimed organizations have IsClaimed = false.
    /// </summary>
    [BsonElement("is_claimed")]
    public bool IsClaimed { get; set; } = true;

    /// <summary>
    /// Cryptographic token for the org claim flow. Generated on org creation.
    /// Cleared (set to null) after successful claim to enforce single-use.
    /// </summary>
    [BsonElement("claim_token")]
    public string? ClaimToken { get; set; }

    /// <summary>
    /// Auth0 User ID of the organization owner (the user who claimed or created the org).
    /// </summary>
    [BsonElement("owner_id")]
    public string? OwnerId { get; set; }

    /// <summary>
    /// Email address of the organization owner. Updated on each login.
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
    /// Subscription and billing plan information
    /// </summary>
    [BsonElement("plan")]
    public Plan? Plan { get; set; }
    
    /// <summary>
    /// Subscription settings
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