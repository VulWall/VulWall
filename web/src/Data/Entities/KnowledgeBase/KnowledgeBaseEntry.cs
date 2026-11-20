using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.KnowledgeBase;

/// <summary>
/// Shared knowledge base entry keyed by finding_type.
/// NOT org-scoped — one entry per unique finding_type across all organizations.
/// Extra fields (for example <c>demo</c> on sample entries from demo-seed) are ignored.
/// </summary>
[BsonIgnoreExtraElements]
public class KnowledgeBaseEntry : IEntity<string>
{
    [BsonId]
    [BsonElement("_id")]
    public string Id { get; set; } = string.Empty;

    [BsonElement("finding_type")]
    public string FindingType { get; set; } = string.Empty;

    [BsonElement("business")]
    public KBBusinessContent? Business { get; set; }

    [BsonElement("technical")]
    public KBTechnicalContent? Technical { get; set; }

    [BsonElement("metadata")]
    public KBMetadata? Metadata { get; set; }

    [BsonElement("model")]
    public string? Model { get; set; }

    [BsonElement("published")]
    public bool Published { get; set; }

    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; }

    [BsonElement("version")]
    public int Version { get; set; } = 1;

    [BsonElement("updated_at")]
    public DateTime? UpdatedAt { get; set; }
}

public class KBBusinessContent
{
    [BsonElement("title")]
    public string? Title { get; set; }

    [BsonElement("summary")]
    public string? Summary { get; set; }

    [BsonElement("impact")]
    public string? Impact { get; set; }

    [BsonElement("urgency")]
    public string? Urgency { get; set; }

    [BsonElement("actions")]
    public List<string>? Actions { get; set; }

    [BsonElement("blog_slug")]
    public string? BlogSlug { get; set; }
}

public class KBTechnicalContent
{
    [BsonElement("title")]
    public string? Title { get; set; }

    [BsonElement("vulnerability_explanation")]
    public string? VulnerabilityExplanation { get; set; }

    [BsonElement("root_cause")]
    public string? RootCause { get; set; }

    [BsonElement("impact")]
    public string? Impact { get; set; }

    [BsonElement("severity")]
    public KBSeverityInfo? Severity { get; set; }

    [BsonElement("affected_components")]
    public List<string>? AffectedComponents { get; set; }

    [BsonElement("affected_versions")]
    public string? AffectedVersions { get; set; }

    [BsonElement("remediation_steps")]
    public List<string>? RemediationSteps { get; set; }

    [BsonElement("verification_steps")]
    public List<string>? VerificationSteps { get; set; }

    [BsonElement("code_examples")]
    public KBCodeExamples? CodeExamples { get; set; }

    [BsonElement("best_practices")]
    public List<string>? BestPractices { get; set; }

    [BsonElement("references")]
    public List<string>? References { get; set; }

    [BsonElement("blog_slug")]
    public string? BlogSlug { get; set; }
}

public class KBSeverityInfo
{
    [BsonElement("level")]
    public string? Level { get; set; }

    [BsonElement("cvss_estimate")]
    public string? CvssEstimate { get; set; }

    [BsonElement("justification")]
    public string? Justification { get; set; }
}

public class KBCodeExamples
{
    [BsonElement("vulnerable")]
    public string? Vulnerable { get; set; }

    [BsonElement("fixed")]
    public string? Fixed { get; set; }

    [BsonElement("language")]
    public string? Language { get; set; }
}

public class KBMetadata
{
    [BsonElement("components")]
    public List<string>? Components { get; set; }

    [BsonElement("owasp_category")]
    public string? OwaspCategory { get; set; }

    [BsonElement("estimated_effort")]
    public string? EstimatedEffort { get; set; }

    [BsonElement("is_exploitable")]
    public bool? IsExploitable { get; set; }

    [BsonElement("tags")]
    public List<string>? Tags { get; set; }
}
