package email_security_scanner

import (
	"context"
	"os"
	"testing"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
)

// TestPublishUniqueFindingsKeysByTypeAndTitle (VULWALL_TEST_REDIS_URI): two findings with one
// finding_type but different titles are two findings for ingestion; both must be reported.
func TestPublishUniqueFindingsKeysByTypeAndTitle(t *testing.T) {
	uri := os.Getenv("VULWALL_TEST_REDIS_URI")
	if uri == "" {
		t.Skip("VULWALL_TEST_REDIS_URI not set")
	}
	opts, err := redis.ParseURL(uri)
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	ctx := context.Background()
	rdb.Del(ctx, shared.StreamSecurityFindings)

	s := &Service{redis: rdb, logger: zap.NewNop(), tracer: otel.Tracer("test")}
	scanID := "scan-1"
	target := ScanTarget{Target: "example.com", DiscoveryID: "d1", OrgID: "org", ScanID: &scanID}
	results := []EmailCheckResult{
		{FindingType: "spf-weak", Title: "SPF allows all senders (+all)"},
		{FindingType: "spf-weak", Title: "SPF has too many DNS lookups"},
		{FindingType: "spf-weak", Title: "SPF allows all senders (+all)"},
	}
	reported, err := s.publishUniqueFindings(ctx, results, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(reported) != 2 {
		t.Fatalf("reported = %+v, want both titles once", reported)
	}
}
