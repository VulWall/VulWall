package findings_ingestion

import (
	"slices"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
)

func TestSetFindingTextAddsScannerText(t *testing.T) {
	doc := bson.M{}
	setFindingText(doc, shared.SecurityFinding{
		Remediation: "Upgrade to 2.4.58.",
		References:  []string{"https://example.org/advisory"},
	})

	if doc["remediation"] != "Upgrade to 2.4.58." {
		t.Fatalf("remediation = %v", doc["remediation"])
	}
	if refs, _ := doc["references"].([]string); !slices.Equal(refs, []string{"https://example.org/advisory"}) {
		t.Fatalf("references = %v", doc["references"])
	}
}

func TestSetFindingTextOmitsEmptyValues(t *testing.T) {
	doc := bson.M{}
	setFindingText(doc, shared.SecurityFinding{})

	if _, ok := doc["remediation"]; ok {
		t.Fatal("empty remediation must not be written (it would clear stored text on update)")
	}
	if _, ok := doc["references"]; ok {
		t.Fatal("empty references must not be written")
	}
}
