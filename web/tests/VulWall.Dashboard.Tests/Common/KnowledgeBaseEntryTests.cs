using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;

namespace VulWall.Dashboard.Tests.Common;

public sealed class KnowledgeBaseEntryTests
{
    // Sample entries from demo-seed carry demo: true; the web app must still read them.
    [Fact]
    public void ReadsAnEntryWithFieldsItDoesNotMap()
    {
        var doc = new BsonDocument
        {
            { "_id", "kb_missing-csp" },
            { "finding_type", "missing-csp" },
            { "published", true },
            { "version", 1 },
            { "created_at", DateTime.UtcNow },
            { "metadata", new BsonDocument { { "estimated_effort", "medium" }, { "is_exploitable", false } } },
            { "demo", true },
        };

        var entry = BsonSerializer.Deserialize<KnowledgeBaseEntry>(doc);

        Assert.Equal("missing-csp", entry.FindingType);
        Assert.True(entry.Published);
        Assert.Equal("medium", entry.Metadata?.EstimatedEffort);
    }
}
