using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Data.Abstractions;

namespace VulWall.Dashboard.Data.Entities.User;

/// <summary>
/// A local login. Self-hosted installs have exactly one: the admin created on the first-run
/// /setup page, stored under the fixed id <see cref="AdminId"/>.
/// </summary>
[BsonIgnoreExtraElements]
public class User : IEntity<string>
{
    /// <summary>
    /// Fixed _id of the single admin. A second insert fails on the unique _id, which makes
    /// first-run setup safe against two concurrent submissions.
    /// </summary>
    public const string AdminId = "admin";

    [BsonId]
    [BsonElement("_id")]
    public string Id { get; set; } = AdminId;

    [BsonElement("email")]
    public string Email { get; set; } = null!;

    /// <summary>BCrypt hash of the password.</summary>
    [BsonElement("password_hash")]
    public string PasswordHash { get; set; } = null!;

    /// <summary>
    /// Random value copied into the auth cookie. Rotating it (logout, password change) invalidates
    /// every cookie issued before. Null on accounts created before it existed.
    /// </summary>
    [BsonElement("security_stamp")]
    public string? SecurityStamp { get; set; }

    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
