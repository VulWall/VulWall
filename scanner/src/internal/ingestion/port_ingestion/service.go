package port_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type Service struct {
	db       *mongo.Database
	redis    *redis.Client
	logger   *zap.Logger
	tracer   trace.Tracer
	orgGuard *shared.OrgGuard
}

func NewService(db *mongo.Database, redis *redis.Client, logger *zap.Logger, orgGuard *shared.OrgGuard) *Service {
	return &Service{
		db:       db,
		redis:    redis,
		logger:   logger,
		tracer:   otel.Tracer("port-ingestion"),
		orgGuard: orgGuard,
	}
}

// ProcessFinding processes a port discovery finding and persists it to MongoDB discoveries collection
func (s *Service) ProcessFinding(ctx context.Context, finding shared.IPDiscoveryFinding) error {
	ctx, span := s.tracer.Start(ctx, "ingest_port_finding",
		trace.WithAttributes(
			attribute.String("org.id", finding.OrgID),
			attribute.String("trace.id", finding.TraceID),
			attribute.String("asset.type", finding.AssetType),
			attribute.String("ip", finding.IP),
			attribute.Int("port", finding.Port),
		),
	)
	defer span.End()

	s.logger.Info("Processing port discovery finding",
		zap.String("trace_id", finding.TraceID),
		zap.String("org_id", finding.OrgID),
		zap.String("source", finding.Source),
		zap.String("ip", finding.IP),
		zap.Int("port", finding.Port),
	)

	// Validate source is present (required)
	if finding.Source == "" {
		s.logger.Warn("Skipping finding: missing source",
			zap.String("trace_id", finding.TraceID),
			zap.String("org_id", finding.OrgID),
			zap.String("ip", finding.IP),
		)
		return nil
	}

	// Drop results for orgs that no longer exist. An org can be deleted mid-scan
	// (Admin/Dashboard cascade delete) while its pipeline is still in flight;
	// without this guard, ingestion would recreate orphan discoveries. Soft-skip
	// (return nil) — an orphan during delete is expected, not a poison message,
	// so dead-lettering it would only flood the dead-letter stream.
	if !s.orgGuard.Exists(ctx, finding.OrgID) {
		s.logger.Info("Skipping finding: organization no longer exists",
			zap.String("trace_id", finding.TraceID),
			zap.String("org_id", finding.OrgID),
			zap.String("ip", finding.IP),
		)
		return nil
	}

	now := time.Now()

	// 1. Ensure IP discovery exists (create if not found with org_id)
	ipDiscoveryID, isNewIP, err := s.ensureIPDiscovery(ctx, finding, now)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("scan.success", false))
		return err
	}

	span.SetAttributes(attribute.Bool("ip.is_new", isNewIP))

	// 2. Publish enrichment job for IP (if it's asset_type="ip" finding or new IP)
	if finding.AssetType == shared.AssetTypeIP || isNewIP {
		if err := s.publishEnrichmentJob(ctx, finding, ipDiscoveryID); err != nil {
			s.logger.Error("Failed to publish enrichment job for IP",
				zap.String("trace_id", finding.TraceID),
				zap.String("ip", finding.IP),
				zap.Error(err),
			)
			// Don't fail if enrichment trigger fails
		}
	}

	// 3. Upsert port discovery (with org_id) - skip if this is an IP finding
	var portDiscoveryID string
	if finding.AssetType == shared.AssetTypePort {
		portDiscoveryID, err = s.upsertPortDiscovery(ctx, finding, ipDiscoveryID, now)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			span.SetAttributes(attribute.Bool("scan.success", false))
			return err
		}

		// 4. Publish scan trigger for active recon scanners (port only). On a CDN edge
		// address it names the site to scan, or is skipped (portTrigger).
		if trigger, reason := portTrigger(finding); reason != "" {
			s.logger.Info("Port scan trigger skipped",
				zap.String("trace_id", finding.TraceID),
				zap.String("ip", finding.IP),
				zap.Int("port", finding.Port),
				zap.String("reason", reason),
			)
			span.SetAttributes(attribute.String("trigger.skip_reason", reason))
		} else if err := s.publishPortScanTrigger(ctx, trigger, portDiscoveryID); err != nil {
			s.logger.Error("Failed to publish port scan trigger",
				zap.String("trace_id", finding.TraceID),
				zap.String("ip", finding.IP),
				zap.Int("port", finding.Port),
				zap.Error(err),
			)
			// Don't fail if trigger fails
		}
	}

	span.SetAttributes(attribute.Bool("scan.success", true))
	span.SetStatus(codes.Ok, "")

	return nil
}

// ensureIPDiscovery ensures an IP discovery exists, creating it if not found
// Returns (discoveryID, isNewIP, error)
func (s *Service) ensureIPDiscovery(ctx context.Context, finding shared.IPDiscoveryFinding, timestamp time.Time) (string, bool, error) {
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Check if IP discovery exists (org-scoped)
	filter := bson.M{
		"org_id":     finding.OrgID,
		"asset_type": shared.AssetTypeIP,
		"ip":         finding.IP,
	}

	var existingIPDiscovery shared.Discovery
	err := collection.FindOne(ctx, filter).Decode(&existingIPDiscovery)

	if err == mongo.ErrNoDocuments {
		// Create new IP discovery using deterministic ID (org-scoped)
		ipDiscoveryID := shared.GenerateIPID(finding.OrgID, finding.IP)
		// Initialize scan_ids array
		scanIDs := []string{}
		if finding.ScanID != nil {
			scanIDs = []string{*finding.ScanID}
		}

		// IP geolocation enrichment now handled by discovery_enrichment service
		var metadata map[string]interface{}
		if provider := shared.CDNProvider(finding.IP); provider != "" {
			metadata = map[string]interface{}{shared.DiscoveryMetaCDNEdge: provider}
		}

		newIPDiscovery := shared.Discovery{
			ID:             ipDiscoveryID,
			OrgID:          finding.OrgID,                   // Organization GUID
			ScanIDs:        scanIDs,                         // Array of scan identifiers
			AssetType:      shared.AssetTypeIP,
			Source:        finding.Source,
			Status:         finding.Status,
			OwnershipStatus: shared.OwnershipStatusVerified,  // Default to verified
			DiscoveredAt:   timestamp,  // When asset was discovered
			// ParentID not set here — finding.ParentID is the IP doc's own ID (used for
			// port→IP linkage), not the domain/subdomain parent. Domain ingestion owns
			// that relationship via upsertIPDiscovery. See VulWall.NightWatch#130.
			IP:             &finding.IP,
			FirstSeen:      timestamp,
			LastSeen:       timestamp,
			Metadata:       metadata,  // Use enriched metadata
		}

		doc := s.buildDiscoveryDocument(newIPDiscovery)

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create IP discovery",
				zap.String("ip", finding.IP),
				zap.Error(err),
			)
			return "", false, err
		}

		s.logger.Info("Created new IP discovery",
			zap.String("discovery_id", ipDiscoveryID),
			zap.String("ip", finding.IP),
		)
		return ipDiscoveryID, true, nil  // Return true for new IP
	}

	if err != nil {
		s.logger.Error("Failed to check existing IP discovery",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return "", false, err
	}

	// IP exists - update last_seen and add scan_id to array; keep the CDN edge mark current
	update := bson.M{
		"$set": bson.M{
			"last_seen": timestamp,
		},
	}
	if provider := shared.CDNProvider(finding.IP); provider != "" {
		update["$set"].(bson.M)["metadata."+shared.DiscoveryMetaCDNEdge] = provider
	} else {
		update["$unset"] = bson.M{"metadata." + shared.DiscoveryMetaCDNEdge: ""}
	}
	// Add scan_id to array if present
	if finding.ScanID != nil {
		update["$addToSet"] = bson.M{
			"scan_ids": *finding.ScanID,
		}
	}

	_, err = collection.UpdateOne(ctx, bson.M{"_id": existingIPDiscovery.ID}, update)
	if err != nil {
		s.logger.Error("Failed to update IP discovery",
			zap.String("ip", finding.IP),
			zap.Error(err),
		)
		return "", false, err
	}

	s.logger.Debug("Updated existing IP discovery",
		zap.String("discovery_id", existingIPDiscovery.ID),
		zap.String("ip", finding.IP),
	)
	return existingIPDiscovery.ID, false, nil  // Return false for existing IP
}

// upsertPortDiscovery creates or updates a port discovery
func (s *Service) upsertPortDiscovery(ctx context.Context, finding shared.IPDiscoveryFinding, ipDiscoveryID string, timestamp time.Time) (string, error) {
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Check if port discovery already exists (org-scoped)
	filter := bson.M{
		"org_id":     finding.OrgID,
		"asset_type": shared.AssetTypePort,
		"ip":         finding.IP,
		"port":       finding.Port,
		"protocol":   finding.Protocol,
	}

	var existingPortDiscovery shared.Discovery
	err := collection.FindOne(ctx, filter).Decode(&existingPortDiscovery)

	if err == mongo.ErrNoDocuments {
		// Create new port discovery using the deterministic ID from the finding
		// Initialize scan_ids array
		scanIDs := []string{}
		if finding.ScanID != nil {
			scanIDs = []string{*finding.ScanID}
		}

		newPortDiscovery := shared.Discovery{
			ID:             finding.DiscoveryID,                // Use provided deterministic ID (org-scoped)
			OrgID:          finding.OrgID,                      // Organization GUID
			ScanIDs:        scanIDs,                            // Array of scan identifiers
			AssetType:      shared.AssetTypePort,
			Source:        finding.Source,
			Status:         finding.Status,
			OwnershipStatus: shared.OwnershipStatusVerified,     // Default to verified
			DiscoveredAt:   timestamp,                          // When asset was discovered
			ParentID:       &ipDiscoveryID,
			IP:             &finding.IP,
			Port:           &finding.Port,
			Protocol:       &finding.Protocol,
			Banner:         finding.Banner,
			ServiceName:    finding.ServiceName,
			Product:        finding.Product,
			Version:        finding.Version,
			FirstSeen:      timestamp,
			LastSeen:       timestamp,
			Metadata:       finding.Metadata,
			PreviousServices: []shared.ServiceHistoryEntry{}, // Empty initially
		}

		doc := s.buildDiscoveryDocument(newPortDiscovery)

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create port discovery",
				zap.String("ip", finding.IP),
				zap.Int("port", finding.Port),
				zap.Error(err),
			)
			return "", err
		}

		s.logger.Info("Created new port discovery",
			zap.String("discovery_id", finding.DiscoveryID),
			zap.String("ip", finding.IP),
			zap.Int("port", finding.Port),
			zap.String("protocol", finding.Protocol),
		)
		return finding.DiscoveryID, nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing port discovery",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return "", err
	}

	// Port exists - check if service has changed
	if err := s.updatePortDiscovery(ctx, &existingPortDiscovery, finding, timestamp); err != nil {
		return "", err
	}

	return existingPortDiscovery.ID, nil
}

// updatePortDiscovery updates port discovery with new scan results and tracks service changes
func (s *Service) updatePortDiscovery(ctx context.Context, discovery *shared.Discovery, finding shared.IPDiscoveryFinding, timestamp time.Time) error {
	collection := s.db.Collection(shared.CollectionDiscoveries)

	// Extract current service characteristics
	currentService := ""
	if discovery.ServiceName != nil {
		currentService = *discovery.ServiceName
	}

	currentProduct := ""
	if discovery.Product != nil {
		currentProduct = *discovery.Product
	}

	currentVersion := ""
	if discovery.Version != nil {
		currentVersion = *discovery.Version
	}

	currentBanner := ""
	if discovery.Banner != nil {
		currentBanner = *discovery.Banner
	}

	// Extract new service characteristics
	newService := ""
	if finding.ServiceName != nil {
		newService = *finding.ServiceName
	}

	newProduct := ""
	if finding.Product != nil {
		newProduct = *finding.Product
	}

	newVersion := ""
	if finding.Version != nil {
		newVersion = *finding.Version
	}

	newBanner := ""
	if finding.Banner != nil {
		newBanner = *finding.Banner
	}

	update := bson.M{
		"$set": bson.M{
			"last_seen": timestamp,
			"status":    finding.Status,
		},
	}
	// Add scan_id to array if present
	if finding.ScanID != nil {
		update["$addToSet"] = bson.M{
			"scan_ids": *finding.ScanID,
		}
	}

	// Check if ANY service characteristic has changed
	serviceChanged := false
	changes := []string{}

	if currentService != newService && currentService != "" {
		serviceChanged = true
		changes = append(changes, "service: "+currentService+"→"+newService)
	}

	if currentProduct != newProduct && currentProduct != "" {
		serviceChanged = true
		changes = append(changes, "product: "+currentProduct+"→"+newProduct)
	}

	if currentVersion != newVersion && currentVersion != "" {
		serviceChanged = true
		changes = append(changes, "version: "+currentVersion+"→"+newVersion)
	}

	if currentBanner != newBanner && currentBanner != "" {
		serviceChanged = true
		changes = append(changes, "banner changed")
	}

	// If ANY characteristic changed, archive the complete old service state
	if serviceChanged {
		// Add current service to history
		historyEntry := shared.ServiceHistoryEntry{
			ServiceName: currentService,
			Product:     discovery.Product,
			Version:     discovery.Version,
			Banner:      discovery.Banner,
			LastSeen:    timestamp,
		}

		update["$push"] = bson.M{
			"previous_services": historyEntry,
		}

		s.logger.Info("Service characteristics changed on port",
			zap.String("discovery_id", discovery.ID),
			zap.String("ip", *discovery.IP),
			zap.Int("port", *discovery.Port),
			zap.Strings("changes", changes),
		)
	}

	// Update current service details
	if finding.ServiceName != nil {
		update["$set"].(bson.M)["service_name"] = finding.ServiceName
	}
	if finding.Banner != nil {
		update["$set"].(bson.M)["banner"] = finding.Banner
	}
	if finding.Product != nil {
		update["$set"].(bson.M)["product"] = finding.Product
	}
	if finding.Version != nil {
		update["$set"].(bson.M)["version"] = finding.Version
	}

	// Merge metadata
	if len(finding.Metadata) > 0 {
		if discovery.Metadata == nil {
			update["$set"].(bson.M)["metadata"] = finding.Metadata
		} else {
			// Merge metadata
			for k, v := range finding.Metadata {
				discovery.Metadata[k] = v
			}
			update["$set"].(bson.M)["metadata"] = discovery.Metadata
		}
	}

	_, err := collection.UpdateOne(ctx, bson.M{"_id": discovery.ID}, update)
	if err != nil {
		s.logger.Error("Failed to update port discovery",
			zap.String("ip", *discovery.IP),
			zap.Int("port", *discovery.Port),
			zap.Error(err),
		)
		return err
	}

	s.logger.Debug("Updated port discovery",
		zap.String("discovery_id", discovery.ID),
		zap.String("ip", *discovery.IP),
		zap.Int("port", *discovery.Port),
	)
	return nil
}

// buildDiscoveryDocument builds a BSON document from a Discovery struct, excluding nil fields
func (s *Service) buildDiscoveryDocument(discovery shared.Discovery) bson.M {
	doc := bson.M{
		"_id":              discovery.ID,
		"org_id":           discovery.OrgID,
		"asset_type":       discovery.AssetType,
		"source":           discovery.Source,
		"status":           discovery.Status,
		"ownership_status": discovery.OwnershipStatus,
		"discovered_at":    discovery.DiscoveredAt,
		"first_seen":       discovery.FirstSeen,
		"last_seen":        discovery.LastSeen,
	}

	if len(discovery.ScanIDs) > 0 {
		doc["scan_ids"] = discovery.ScanIDs
	}

	if discovery.ParentID != nil {
		doc["parent_id"] = discovery.ParentID
	}

	if len(discovery.Metadata) > 0 {
		doc["metadata"] = discovery.Metadata
	}

	// Asset-type specific fields
	if discovery.IP != nil {
		doc["ip"] = discovery.IP
	}
	if discovery.Port != nil {
		doc["port"] = discovery.Port
	}
	if discovery.Protocol != nil {
		doc["protocol"] = discovery.Protocol
	}
	if discovery.Banner != nil {
		doc["banner"] = discovery.Banner
	}
	if discovery.ServiceName != nil {
		doc["service_name"] = discovery.ServiceName
	}
	if discovery.Product != nil {
		doc["product"] = discovery.Product
	}
	if discovery.Version != nil {
		doc["version"] = discovery.Version
	}
	if len(discovery.PreviousServices) > 0 {
		doc["previous_services"] = discovery.PreviousServices
	}

	return doc
}

// publishEnrichmentJob publishes an enrichment job for an IP to the enrichment queue
func (s *Service) publishEnrichmentJob(ctx context.Context, finding shared.IPDiscoveryFinding, ipDiscoveryID string) error {
	// Build enrichment job (IP only - no ports)
	enrichmentJob := shared.EnrichmentJob{
		TraceID:      finding.TraceID,
		TraceContext: telemetry.InjectTraceContext(ctx), // Inject trace context for span linking
		ScanID:       finding.ScanID,
		OrgID:        finding.OrgID,
		DiscoveryID:  ipDiscoveryID,
		AssetType:    shared.AssetTypeIP,
		IP:           finding.IP,
		Created:      time.Now(),
	}

	// Publish to enrichment job queue WITHOUT MAXLEN (queues should not be trimmed)
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamDiscoveryEnrichmentQueue, enrichmentJob, 0); err != nil {
		return fmt.Errorf("failed to publish enrichment job: %w", err)
	}

	s.logger.Debug("Published enrichment job for IP",
		zap.String("trace_id", finding.TraceID),
		zap.String("discovery_id", ipDiscoveryID),
		zap.String("ip", finding.IP),
	)

	return nil
}

// portTrigger returns the port_scan_triggers message for an open port (nuclei is its only
// consumer), or a reason to publish none. The port discovery itself is stored either way.
//
// A shared CDN edge address (shared.CDNProvider: Cloudflare, Fastly, CloudFront, Azure Front
// Door) answers only requests that name a site; nuclei by IP waits minutes on every port and
// drops the target. So on such an address:
//   - 80 and 443 get no trigger: the names behind it are scanned on 80 and 443 by hostname
//     (domain_scan_triggers).
//   - another port gets a trigger with ScanHost set to the name of this scan that resolved to
//     the address (TargetDomain), and nuclei scans <scheme>://<name>:<port>: the CDN forwards
//     that port to the name's origin.
//   - without such a name (the address is a direct IP asset) it gets no trigger.
//
// Any other address keeps the IP scan on every port: a server by bare IP can show a default
// virtual host that its names do not.
func portTrigger(finding shared.IPDiscoveryFinding) (trigger shared.IPDiscoveryFinding, skipReason string) {
	provider := shared.CDNProvider(finding.IP)
	switch {
	case provider == "":
		return finding, ""
	case finding.Port == 80 || finding.Port == 443:
		return finding, "cdn_edge_web_port:" + provider
	case finding.TargetDomain == "":
		return finding, "cdn_edge_no_name:" + provider
	}
	finding.ScanHost = finding.TargetDomain
	return finding, ""
}

// publishPortScanTrigger publishes a scan trigger for active recon scanners
// This is published AFTER persisting the port to ensure proper trace hierarchy
func (s *Service) publishPortScanTrigger(ctx context.Context, finding shared.IPDiscoveryFinding, portDiscoveryID string) error {
	// Re-publish the finding with the current span context (ingest_port_finding)
	// This ensures active recon scanners become children of this span
	trigger := finding
	trigger.DiscoveryID = portDiscoveryID
	trigger.TraceContext = telemetry.InjectTraceContext(ctx) // Inject current context for proper hierarchy

	// Publish to port scan triggers stream with MAXLEN to prevent unbounded growth
	if err := redisx.PublishToStream(ctx, s.redis, shared.StreamPortScanTriggers, trigger, 10000); err != nil {
		return fmt.Errorf("failed to publish port scan trigger: %w", err)
	}

	s.logger.Debug("Published port scan trigger",
		zap.String("trace_id", finding.TraceID),
		zap.String("discovery_id", portDiscoveryID),
		zap.String("ip", finding.IP),
		zap.Int("port", finding.Port),
	)

	return nil
}
