package scan_coordinator

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// ErrOrgNotFound indicates a scan was requested for an organization that no
// longer exists — e.g., deleted between a cron enqueue and execution.
var ErrOrgNotFound = errors.New("organization not found")

// ErrScanInProgress indicates the organization already has a queued scan, so
// nothing was started or queued. The queued scan reads the assets when it
// starts, so it covers everything a new scan would.
var ErrScanInProgress = errors.New("scan already queued for organization")

// ErrScanQueued indicates the organization had a pending or running scan, so a
// queued scan was inserted instead of starting one. The queued-scan poller
// starts it after the running scan finishes.
var ErrScanQueued = errors.New("scan queued after the running scan")

// startedStatuses are the states of a scan whose pipeline is in flight; the
// one-scan-per-organization guard checks them.
var startedStatuses = []string{shared.StatusPending, shared.StatusRunning}

// scanStore is the MongoDB access the coordinator needs to start scans. The
// production implementation is mongoScanStore; tests use a fake.
type scanStore interface {
	orgExists(ctx context.Context, orgID string) (bool, error)
	// orgScanSettings returns the organization's scan schedule settings.
	orgScanSettings(ctx context.Context, orgID string) (shared.ScanSettings, error)
	hasScanIn(ctx context.Context, orgID string, statuses []string) (bool, error)
	orgAssets(ctx context.Context, orgID string) ([]shared.Asset, error)
	// knownSubdomains returns the names of the org's subdomain discoveries whose parent is
	// parentID and that a scan saw within knownSubdomainWindow.
	knownSubdomains(ctx context.Context, orgID, parentID string) ([]string, error)
	insertScan(ctx context.Context, scan shared.Scan) error
	queuedScans(ctx context.Context) ([]shared.Scan, error)
	// claimQueuedScan applies set to the scan only while it is still queued.
	// It reports false when another writer changed or deleted the scan first.
	claimQueuedScan(ctx context.Context, scanID string, set bson.M) (bool, error)
	setScanFields(ctx context.Context, scanID string, set bson.M) error
	// setStartedScans applies set to every pending or running scan and
	// returns how many it changed.
	setStartedScans(ctx context.Context, set bson.M) (int64, error)
}

// jobPublisher publishes one discovery job to a Redis stream.
type jobPublisher func(ctx context.Context, stream string, job any) error

// Service handles scan coordination logic
type Service struct {
	store   scanStore
	publish jobPublisher
	logger  *zap.Logger
	tracer  trace.Tracer

	// startMu serializes the check-then-start sequence of the cron scheduler
	// and the queued-scan poller, which run in different goroutines. Without
	// it both could see "no active scan" and start two pipelines for one org.
	startMu sync.Mutex
}

// NewService creates a new scan coordinator service
func NewService(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		store: mongoScanStore{db: db},
		publish: func(ctx context.Context, stream string, job any) error {
			// Job queues are never trimmed (maxLen 0).
			return redisx.PublishToStream(ctx, redisClient, stream, job, 0)
		},
		logger: logger,
		tracer: otel.Tracer("scan-coordinator"),
	}
}

// ScanRequest represents a request to trigger a scan for an organization.
type ScanRequest struct {
	OrgID       string // Organization GUID
	Type        string // "scheduled", "requested"
	TriggeredBy string // "system" or user ID
}

// TriggerScan creates a scan record and publishes discovery jobs for an
// organization. The cron scheduler uses it; scans requested from the web UI
// arrive as queued documents and go through StartQueuedScans instead.
// Returns the scan ID on success.
//
// While the organization has a queued scan it does nothing and returns
// ErrScanInProgress. While it has a pending or running scan it queues one
// (the same one-queued-scan-per-organization rule as the web app) and returns
// its ID with ErrScanQueued, so a long scan does not swallow a scheduled one.
func (s *Service) TriggerScan(ctx context.Context, req ScanRequest) (string, error) {
	ctx, span := s.tracer.Start(ctx, "trigger_scan",
		trace.WithAttributes(
			attribute.String("org.id", req.OrgID),
		),
	)
	defer span.End()

	s.logger.Info("Triggering scan for organization",
		zap.String("org_id", req.OrgID),
		zap.String("type", req.Type),
		zap.String("triggered_by", req.TriggeredBy),
	)

	s.startMu.Lock()
	defer s.startMu.Unlock()

	// Verify the org still exists before creating a scan record or publishing
	// jobs. A stale cron entry could otherwise create an orphan scan for a
	// deleted org.
	exists, err := s.store.orgExists(ctx, req.OrgID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to verify organization: %w", err)
	}
	if !exists {
		span.SetStatus(codes.Error, ErrOrgNotFound.Error())
		s.logger.Warn("Skipping scan trigger: organization not found",
			zap.String("org_id", req.OrgID),
		)
		return "", ErrOrgNotFound
	}

	// One active scan per organization. A queued scan already covers every
	// asset, so there is nothing to add.
	queued, err := s.store.hasScanIn(ctx, req.OrgID, []string{shared.StatusQueued})
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to check queued scans: %w", err)
	}
	if queued {
		span.SetStatus(codes.Error, ErrScanInProgress.Error())
		s.logger.Info("Skipping scan trigger: a scan is already queued",
			zap.String("org_id", req.OrgID),
		)
		return "", ErrScanInProgress
	}

	// A running scan must not get a second pipeline: queue this one behind it.
	busy, err := s.store.hasScanIn(ctx, req.OrgID, startedStatuses)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to check running scans: %w", err)
	}
	if busy {
		return s.queueScan(ctx, req)
	}

	assets, err := s.store.orgAssets(ctx, req.OrgID)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to get org assets: %w", err)
	}
	targetedAssets := s.targetsFor(req.OrgID, assets)

	now := time.Now()
	scanID := uuid.New().String()
	scan := shared.Scan{
		ID:             scanID,
		OrgID:          req.OrgID,
		Status:         shared.StatusRunning,
		Type:           req.Type,
		TriggeredBy:    req.TriggeredBy,
		StartedAt:      &now,
		CreatedAt:      now,
		UpdatedAt:      now,
		TargetedAssets: targetedAssets,
		Stats: shared.ScanStats{
			TotalAssets: len(targetedAssets),
		},
	}

	if err := s.store.insertScan(ctx, scan); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to create scan: %w", err)
	}

	span.SetAttributes(attribute.String("scan.id", scanID))

	s.logger.Info("Created new scan record",
		zap.String("scan_id", scanID),
		zap.String("org_id", req.OrgID),
		zap.Int("targeted_assets_count", len(targetedAssets)),
	)

	if err := s.publishDiscoveryJobs(ctx, req.OrgID, scanID, assets); err != nil {
		s.markFailed(ctx, scanID, err)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to publish discovery jobs: %w", err)
	}

	span.SetStatus(codes.Ok, "")

	s.logger.Info("Successfully triggered scan",
		zap.String("scan_id", scanID),
		zap.String("org_id", req.OrgID),
		zap.Int("jobs_published", len(assets)),
	)

	return scanID, nil
}

// queueScan inserts a queued scan for req, as the web app does for a scan
// requested while another runs. The queued-scan poller claims it once the
// running scan is done. The web app's unique partial index allows one queued
// scan per organization, so a duplicate-key error means another writer queued
// one first: that scan covers all assets too.
func (s *Service) queueScan(ctx context.Context, req ScanRequest) (string, error) {
	now := time.Now()
	scan := shared.Scan{
		ID:          uuid.New().String(),
		OrgID:       req.OrgID,
		Status:      shared.StatusQueued,
		Type:        req.Type,
		TriggeredBy: req.TriggeredBy,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := s.store.insertScan(ctx, scan); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			s.logger.Info("Skipping scan trigger: a scan was queued concurrently",
				zap.String("org_id", req.OrgID),
			)
			return "", ErrScanInProgress
		}
		return "", fmt.Errorf("failed to queue scan: %w", err)
	}
	s.logger.Info("Queued scan: the organization has a running scan",
		zap.String("scan_id", scan.ID),
		zap.String("org_id", req.OrgID),
		zap.String("type", req.Type),
	)
	return scan.ID, ErrScanQueued
}

// targetsFor builds the targeted_assets audit trail for a scan. Assets with a
// missing value are skipped (and are skipped again by publishDiscoveryJobs).
func (s *Service) targetsFor(orgID string, assets []shared.Asset) []shared.AssetTarget {
	targets := make([]shared.AssetTarget, 0, len(assets))
	for _, asset := range assets {
		target := shared.AssetTarget{AssetID: asset.ID, Type: asset.Type}
		switch {
		case asset.Type == "domain" && asset.Domain != nil:
			target.Value = *asset.Domain
		case asset.Type == "ip" && asset.IP != nil:
			target.Value = *asset.IP
		default:
			s.logger.Warn("Asset missing required field, skipping from targeted assets",
				zap.String("org_id", orgID),
				zap.String("asset_id", asset.ID),
				zap.String("type", asset.Type),
			)
			continue
		}
		targets = append(targets, target)
	}
	return targets
}

// markFailed moves a scan to "failed" so it does not block its organization
// until the monitor's safety timeout. Best-effort: errors are only logged.
//
// The write uses a context detached from ctx: the usual cause is a publish
// that failed because ctx was cancelled (shutdown), and the scan must still be
// closed then, or it stays "running" until the safety timeout.
func (s *Service) markFailed(ctx context.Context, scanID string, cause error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), markFailedTimeout)
	defer cancel()

	now := time.Now()
	err := s.store.setScanFields(ctx, scanID, bson.M{
		"status":       shared.StatusFailed,
		"completed_at": now,
		"updated_at":   now,
	})
	s.logger.Error("Scan failed to start",
		zap.String("scan_id", scanID),
		zap.NamedError("cause", cause),
		zap.Error(err),
	)
}

// CloseInterruptedScans closes every scan that was pending or running when the
// scanner stopped. It must run once at startup, before the scan monitor.
//
// A restart loses the scan's in-flight work, so letting the monitor finish it
// later would compare a partial result with the previous scan and resolve
// findings that were simply not scanned again. The scan is closed as "failed"
// with status_reason "interrupted_by_restart", the same outcome the web app
// already shows for any failed scan; findings are not touched and the next
// scan compares against the last complete one.
//
// This assumes one scanner process per database, which is how the self-hosted
// stack runs.
func (s *Service) CloseInterruptedScans(ctx context.Context) (int64, error) {
	now := time.Now()
	n, err := s.store.setStartedScans(ctx, bson.M{
		"status":              shared.StatusFailed,
		"status_reason":       shared.ScanReasonInterruptedByRestart,
		"completion_reason":   shared.ScanReasonInterruptedByRestart,
		"findings_reconciled": false,
		"completed_at":        now,
		"updated_at":          now,
	})
	if err != nil {
		return 0, fmt.Errorf("close interrupted scans: %w", err)
	}
	if n > 0 {
		s.logger.Warn("Closed scans interrupted by a restart as failed; their findings are unchanged",
			zap.Int64("scans", n))
	}
	return n, nil
}

// mongoScanStore implements scanStore against MongoDB.
type mongoScanStore struct {
	db *mongo.Database
}

// orgExists reports whether an organization document exists for orgID.
func (m mongoScanStore) orgExists(ctx context.Context, orgID string) (bool, error) {
	coll := m.db.Collection(shared.CollectionOrganizations)
	err := coll.FindOne(ctx, shared.OrgIDFilter(orgID)).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// orgScanSettings returns the scan_settings of the organization.
func (m mongoScanStore) orgScanSettings(ctx context.Context, orgID string) (shared.ScanSettings, error) {
	var org shared.Organization
	err := m.db.Collection(shared.CollectionOrganizations).FindOne(ctx, shared.OrgIDFilter(orgID),
		options.FindOne().SetProjection(bson.M{"scan_settings": 1})).Decode(&org)
	return org.ScanSettings, err
}

// hasScanIn reports whether the organization has a scan in one of statuses.
// The monitor moves stuck pending/running scans to done on timeout, so a
// crashed pipeline cannot block an organization forever.
func (m mongoScanStore) hasScanIn(ctx context.Context, orgID string, statuses []string) (bool, error) {
	coll := m.db.Collection(shared.CollectionScans)
	err := coll.FindOne(ctx, bson.M{
		"org_id": orgID,
		"status": bson.M{"$in": statuses},
	}).Err()
	if err == mongo.ErrNoDocuments {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// orgAssets retrieves all enabled user-added assets for an organization.
func (m mongoScanStore) orgAssets(ctx context.Context, orgID string) ([]shared.Asset, error) {
	cursor, err := m.db.Collection(shared.CollectionAssets).Find(ctx, bson.M{
		"org_id":  orgID,
		"enabled": true,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var assets []shared.Asset
	if err := cursor.All(ctx, &assets); err != nil {
		return nil, err
	}
	return assets, nil
}

// knownSubdomainWindow bounds the known names a discovery job carries: names not seen for
// this long are no longer checked (their findings are long resolved or confirmed gone).
const knownSubdomainWindow = 90 * 24 * time.Hour

// maxKnownSubdomains caps the names one job carries, to bound the message size.
const maxKnownSubdomains = 10000

func (m mongoScanStore) knownSubdomains(ctx context.Context, orgID, parentID string) ([]string, error) {
	cursor, err := m.db.Collection(shared.CollectionDiscoveries).Find(ctx,
		bson.M{
			"org_id":     orgID,
			"asset_type": shared.AssetTypeSubdomain,
			"parent_id":  parentID,
			"last_seen":  bson.M{"$gte": time.Now().Add(-knownSubdomainWindow)},
		},
		options.Find().
			SetProjection(bson.M{"subdomain": 1}).
			SetSort(bson.D{{Key: "last_seen", Value: -1}}).
			SetLimit(maxKnownSubdomains),
	)
	if err != nil {
		return nil, err
	}
	var docs []struct {
		Subdomain string `bson:"subdomain"`
	}
	if err := cursor.All(ctx, &docs); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(docs))
	for _, d := range docs {
		if d.Subdomain != "" {
			names = append(names, d.Subdomain)
		}
	}
	return names, nil
}

// insertScan inserts a new scan record.
func (m mongoScanStore) insertScan(ctx context.Context, scan shared.Scan) error {
	_, err := m.db.Collection(shared.CollectionScans).InsertOne(ctx, scan)
	return err
}

// queuedScans returns queued scans, oldest first.
func (m mongoScanStore) queuedScans(ctx context.Context) ([]shared.Scan, error) {
	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: 1}}).
		SetLimit(QueuedScanBatchSize)
	cursor, err := m.db.Collection(shared.CollectionScans).Find(ctx, bson.M{"status": shared.StatusQueued}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var scans []shared.Scan
	if err := cursor.All(ctx, &scans); err != nil {
		return nil, err
	}
	return scans, nil
}

// claimQueuedScan updates the scan only while its status is still "queued".
// The status in the filter makes the claim atomic.
func (m mongoScanStore) claimQueuedScan(ctx context.Context, scanID string, set bson.M) (bool, error) {
	res, err := m.db.Collection(shared.CollectionScans).UpdateOne(ctx,
		bson.M{"_id": scanID, "status": shared.StatusQueued},
		bson.M{"$set": set},
	)
	if err != nil {
		return false, err
	}
	return res.MatchedCount == 1, nil
}

// setScanFields applies set to one scan.
func (m mongoScanStore) setScanFields(ctx context.Context, scanID string, set bson.M) error {
	_, err := m.db.Collection(shared.CollectionScans).UpdateOne(ctx, bson.M{"_id": scanID}, bson.M{"$set": set})
	return err
}

// setStartedScans applies set to every pending or running scan.
func (m mongoScanStore) setStartedScans(ctx context.Context, set bson.M) (int64, error) {
	res, err := m.db.Collection(shared.CollectionScans).UpdateMany(ctx,
		bson.M{"status": bson.M{"$in": startedStatuses}},
		bson.M{"$set": set},
	)
	if err != nil {
		return 0, err
	}
	return res.ModifiedCount, nil
}

// publishDiscoveryJobs publishes discovery jobs to Redis for each asset
func (s *Service) publishDiscoveryJobs(ctx context.Context, orgID, scanID string, assets []shared.Asset) error {
	ctx, span := s.tracer.Start(ctx, "publish_discovery_jobs")
	defer span.End()

	traceID := uuid.New().String()

	domainCount := 0
	ipCount := 0
	failed := 0

	for _, asset := range assets {
		switch asset.Type {
		case "domain":
			// Publish domain discovery job
			if asset.Domain == nil {
				s.logger.Warn("Domain asset missing domain field",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
				)
				continue
			}

			// Sanitize domain to strip URL scheme (https://) and paths
			host := sanitizeDomain(*asset.Domain)

			// The names earlier scans saw below this domain: discovery checks them even when
			// subfinder misses them. Without them the job still runs; it only cannot confirm
			// a known name gone, so its findings stay open.
			known, err := s.store.knownSubdomains(ctx, orgID, shared.GenerateDomainID(orgID, host))
			if err != nil {
				s.logger.Warn("Failed to load known subdomains; discovery will check subfinder's names only",
					zap.String("org_id", orgID), zap.String("host", host), zap.Error(err))
			}

			job := shared.DiscoveryJob{
				TraceID:         traceID,
				TraceContext:    telemetry.InjectTraceContext(ctx), // Inject trace context for distributed tracing
				ScanID:          &scanID,
				OrgID:           orgID,
				AssetID:         asset.ID,
				Host:            host,
				KnownSubdomains: known,
				Created:         time.Now(),
			}

			if err := s.publish(ctx, shared.StreamDomainDiscoveryQueue, job); err != nil {
				failed++
				s.logger.Error("Failed to publish domain discovery job",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
					zap.Error(err),
				)
				continue
			}

			domainCount++

			s.logger.Debug("Published domain discovery job",
				zap.String("scan_id", scanID),
				zap.String("asset_id", asset.ID),
				zap.String("host", host),
				zap.String("original", *asset.Domain),
			)

		case "ip":
			// Publish IP discovery job (port scanning)
			if asset.IP == nil {
				s.logger.Warn("IP asset missing IP field",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
				)
				continue
			}

			job := shared.IPDiscoveryJob{
				TraceID:      traceID,
				TraceContext: telemetry.InjectTraceContext(ctx), // Inject trace context for distributed tracing
				ScanID:       &scanID,
				OrgID:        orgID,
				IP:           *asset.IP,
				Created:      time.Now(),
			}

			if err := s.publish(ctx, shared.StreamIPDiscoveryQueue, job); err != nil {
				failed++
				s.logger.Error("Failed to publish IP discovery job",
					zap.String("org_id", orgID),
					zap.String("asset_id", asset.ID),
					zap.Error(err),
				)
				continue
			}

			ipCount++

			s.logger.Debug("Published IP discovery job",
				zap.String("scan_id", scanID),
				zap.String("asset_id", asset.ID),
				zap.String("ip", *asset.IP),
			)

		default:
			s.logger.Warn("Unknown asset type",
				zap.String("scan_id", scanID),
				zap.String("asset_id", asset.ID),
				zap.String("type", asset.Type),
			)
		}
	}

	span.SetAttributes(
		attribute.Int("jobs.domain_count", domainCount),
		attribute.Int("jobs.ip_count", ipCount),
		attribute.Int("jobs.total_count", domainCount+ipCount),
	)

	// A scan whose every job failed to publish can never make progress.
	if failed > 0 && domainCount+ipCount == 0 {
		err := fmt.Errorf("all %d discovery jobs failed to publish", failed)
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "")

	return nil
}

// sanitizeDomain extracts the hostname from a domain string, stripping any URL scheme or path.
// Examples: "https://example.com" -> "example.com", "example.com/path" -> "example.com"
func sanitizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)

	// If it looks like a URL (has scheme), parse it
	if strings.Contains(domain, "://") {
		if parsed, err := url.Parse(domain); err == nil && parsed.Host != "" {
			return parsed.Host
		}
	}

	// Strip any path component
	if idx := strings.Index(domain, "/"); idx > 0 {
		domain = domain[:idx]
	}

	return domain
}
