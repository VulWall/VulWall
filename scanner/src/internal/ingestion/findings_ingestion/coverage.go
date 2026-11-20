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

	collection := s.db.Collection(shared.CollectionScanCoverage,
		options.Collection().SetWriteConcern(writeconcern.Majority()))
	filter := bson.M{"scan_id": *msg.ScanID, "source": cov.Source, "discovery_id": cov.DiscoveryID}
	_, err := collection.UpdateOne(ctx, filter, coverageUpdate(msg.OrgID, *cov, time.Now()),
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
func coverageUpdate(orgID string, cov shared.ScanCoverage, now time.Time) mongo.Pipeline {
	reported := bson.A{}
	for _, k := range cov.Reported {
		reported = append(reported, bson.M{"finding_type": k.FindingType, "title": k.Title})
	}
	status := bson.M{"$cond": bson.A{
		bson.M{"$eq": bson.A{"$status", shared.CoverageError}}, shared.CoverageError, cov.Status,
	}}
	set := bson.M{
		"org_id":     orgID,
		"status":     status,
		"target":     cov.Target,
		"reported":   bson.M{"$setUnion": bson.A{bson.M{"$ifNull": bson.A{"$reported", bson.A{}}}, reported}},
		"created_at": bson.M{"$ifNull": bson.A{"$created_at", now}},
		"updated_at": now,
	}
	if cov.Error != "" {
		set["error"] = cov.Error
	}
	return mongo.Pipeline{{{Key: "$set", Value: set}}}
}
