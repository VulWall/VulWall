package demoseed

import (
	"encoding/json"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/enrichers/knowledge_base"
	"go.mongodb.org/mongo-driver/bson"
)

// The sample entries stand for what the KB engine writes, so each must pass
// the engine's own check. A failure here means the samples or the check's
// bounds are wrong.
func TestSampleKBEntriesPassValidateEntry(t *testing.T) {
	for _, doc := range knowledgeBase() {
		t.Run(doc.FindingType, func(t *testing.T) {
			raw, err := bson.Marshal(struct {
				Business  kbBusiness  `bson:"business"`
				Technical kbTechnical `bson:"technical"`
				Metadata  kbMetadata  `bson:"metadata"`
			}{doc.Business, doc.Technical, doc.Metadata})
			if err != nil {
				t.Fatal(err)
			}
			var entry bson.M
			if err := bson.Unmarshal(raw, &entry); err != nil {
				t.Fatal(err)
			}
			entryJSON, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			if err := knowledge_base.ValidateEntry(entryJSON); err != nil {
				t.Error(err)
			}
		})
	}
}
