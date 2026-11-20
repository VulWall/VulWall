package kb_ingestion

import (
	"testing"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
)

func TestKBUpsertUpdate_NewEntriesArePublished(t *testing.T) {
	now := time.Now()
	update := kbUpsertUpdate(shared.KBGenerationResult{FindingType: "missing_hsts"}, now)

	onInsert, ok := update["$setOnInsert"].(bson.M)
	if !ok {
		t.Fatalf("$setOnInsert missing or wrong type: %#v", update["$setOnInsert"])
	}
	if got := onInsert["published"]; got != true {
		t.Errorf("published on insert = %v, want true", got)
	}
	if got := onInsert["_id"]; got != "kb_missing_hsts" {
		t.Errorf("_id on insert = %v, want kb_missing_hsts", got)
	}
}

func TestKBUpsertUpdate_RegenerationDoesNotTouchPublished(t *testing.T) {
	update := kbUpsertUpdate(shared.KBGenerationResult{FindingType: "x"}, time.Now())

	set, ok := update["$set"].(bson.M)
	if !ok {
		t.Fatalf("$set missing or wrong type: %#v", update["$set"])
	}
	if _, present := set["published"]; present {
		t.Error("$set must not contain published; an existing entry keeps its flag")
	}
}
