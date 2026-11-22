package findings_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"go.uber.org/zap"
)

// RecordCoverage stores a coverage message in scan_coverage, one record per
// (scan_id, source, discovery_id). The scan monitor resolves findings only on these records.
//
// A target can be checked twice in one scan (a host that is both an asset and a subdomain of
// another asset gets two triggers), and a message can be redelivered. The records merge so
// that doubt wins: once a run reported "error" the record stays "error", and the reported
// finding keys are the union of all runs.
func (s *Service) RecordCoverage(ctx context.Context, msg shared.SecurityFinding) error {
	cov := msg.Coverage
	if msg.ScanID == nil || *msg.ScanID == "" || cov.DiscoveryID == "" || cov.Source == "" {
		// Without a scan or a target the record cannot be used: nothing to store.
		s.logger.Warn("Skipping coverage without scan_id, discovery_id or source",
			zap.String("org_id", msg.OrgID), zap.String("source", cov.Source))
		return nil
	}
	if !s.orgGuard.Exists(ctx, msg.OrgID) {
		return nil
	}
	// Not for a discovery that an asset delete removes or has removed (discoveryStateOf). A
	// missing discovery is kept for the sources whose coverage can come before it.
	state, err := s.discoveryStateOf(ctx, msg.OrgID, cov.DiscoveryID)
	if err != nil {
		return err
	}
	if state == discoveryDeleting || (state == discoveryMissing && !coverageMayPrecedeDiscovery(cov.Source)) {
		s.logger.Info("Skipping coverage: discovery no longer exists or is being deleted",
			zap.String("org_id", msg.OrgID),
			zap.String("scan_id", *msg.ScanID),
			zap.String("source", cov.Source),
			zap.String("discovery_id", cov.DiscoveryID),
			zap.Bool("delete_pending", state == discoveryDeleting),
		)
		return nil
	}

	collection := s.db.Collection(shared.CollectionScanCoverage,
		options.Collection().SetWriteConcern(writeconcern.Majority()))
	filter := bson.M{"scan_id": *msg.ScanID, "source": cov.Source, "discovery_id": cov.DiscoveryID}
	_, err = collection.UpdateOne(ctx, filter, coverageUpdate(msg.OrgID, *cov, time.Now()),
		options.Update().SetUpsert(true))
	if mongo.IsDuplicateKeyError(err) {
		// Two upserts of a new record raced; the second one now finds the record.
		_, err = collection.UpdateOne(ctx, filter, coverageUpdate(msg.OrgID, *cov, time.Now()))
	}
	if err != nil {
		return fmt.Errorf("failed to record scan coverage: %w", err)
	}
	s.logger.Debug("Recorded scan coverage",
		zap.String("scan_id", *msg.ScanID),
		zap.String("source", cov.Source),
		zap.String("discovery_id", cov.DiscoveryID),
		zap.String("status", cov.Status),
		zap.Int("reported", len(cov.Reported)),
	)
	return nil
}

// coverageUpdate is the update pipeline that merges cov into the record: the status stays
// "error" once any run reported it, and reported is the union of all runs.
//
// In an update pipeline a string that starts with "$" is a field path or a variable, not a
// value. Target, error and finding titles come from the scanned site and its tools, so every
// value from the message goes in as {$literal: ...}.
func coverageUpdate(orgID string, cov shared.ScanCoverage, now time.Time) mongo.Pipeline {
	// bson.D, not bson.M: $setUnion compares documents field by field in order, and a map
	// would write the two fields in a random order, so one key could be stored twice.
	reported := bson.A{}
	for _, k := range cov.Reported {
		reported = append(reported, bson.D{{Key: "finding_type", Value: k.FindingType}, {Key: "title", Value: k.Title}})
	}
	status := bson.M{"$cond": bson.A{
		bson.M{"$eq": bson.A{"$status", shared.CoverageError}}, shared.CoverageError, literal(cov.Status),
	}}
	set := bson.M{
		"org_id":     literal(orgID),
		"status":     status,
		"target":     literal(cov.Target),
		"reported":   bson.M{"$setUnion": bson.A{bson.M{"$ifNull": bson.A{"$reported", bson.A{}}}, literal(reported)}},
		"created_at": bson.M{"$ifNull": bson.A{"$created_at", now}},
		"updated_at": now,
	}
	if cov.Error != "" {
		set["error"] = literal(cov.Error)
	}
	return mongo.Pipeline{{{Key: "$set", Value: set}}}
}

// literal makes v a plain value inside an aggregation expression.
func literal(v any) bson.M { return bson.M{"$literal": v} }
