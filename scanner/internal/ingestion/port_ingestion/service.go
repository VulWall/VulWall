package port_ingestion

import (
	"context"
	"time"

	"github.com/vulwall/scanners/internal/ingestion/services"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type Service struct {
	db       *mongo.Database
	logger   *zap.Logger
	enricher *services.IPEnricher
}

func NewService(db *mongo.Database, ipEnrichmentDBPath string, logger *zap.Logger) *Service {
	// Initialize enricher (graceful failure if DB missing)
	enricher, err := services.NewIPEnricher(ipEnrichmentDBPath)
	if err != nil {
		logger.Warn("Failed to initialize IP enricher, continuing without enrichment",
			zap.String("db_path", ipEnrichmentDBPath),
			zap.Error(err))
		enricher = nil
	} else {
		logger.Info("IP enrichment enabled",
			zap.String("db_path", ipEnrichmentDBPath))
	}

	return &Service{
		db:       db,
		logger:   logger,
		enricher: enricher,
	}
}

// ProcessFinding processes a port discovery finding and persists it to MongoDB discoveries collection
func (s *Service) ProcessFinding(ctx context.Context, finding shared.IPDiscoveryFinding) error {
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

	now := time.Now()

	// 1. Ensure IP discovery exists (create if not found with org_id)
	ipDiscoveryID, err := s.ensureIPDiscovery(ctx, finding, now)
	if err != nil {
		return err
	}

	// 2. Upsert port discovery (with org_id)
	_, err = s.upsertPortDiscovery(ctx, finding, ipDiscoveryID, now)
	if err != nil {
		return err
	}

	return nil
}

// ensureIPDiscovery ensures an IP discovery exists, creating it if not found
func (s *Service) ensureIPDiscovery(ctx context.Context, finding shared.IPDiscoveryFinding, timestamp time.Time) (string, error) {
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

		// Enrich IP with geolocation data
		var metadata map[string]interface{}
		if s.enricher != nil {
			if ipInfo, err := s.enricher.Enrich(finding.IP); err == nil {
				metadata = map[string]interface{}{
					"geo": map[string]interface{}{
						"continent": ipInfo.Continent,
						"country":   ipInfo.Country,
						"isp":       ipInfo.ISP,
					},
				}
				s.logger.Debug("IP enriched with geolocation",
					zap.String("ip", finding.IP),
					zap.String("continent", ipInfo.Continent),
					zap.String("country", ipInfo.Country),
					zap.String("isp", ipInfo.ISP))
			} else {
				s.logger.Debug("Failed to enrich IP", zap.String("ip", finding.IP), zap.Error(err))
			}
		}

		newIPDiscovery := shared.Discovery{
			ID:             ipDiscoveryID,
			OrgID:          finding.OrgID,                   // Organization GUID
			ScanIDs:        scanIDs,                         // Array of scan identifiers
			AssetType:      shared.AssetTypeIP,
			Source:         finding.Source,
			Status:         finding.Status,
			OrgAssetStatus: shared.OrgAssetStatusConfirmed,  // Default to confirmed
			AssignedAt:     timestamp,                       // When assigned to org
			ParentID:       finding.ParentID,                // From IPDiscoveryJob.ParentID
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
			return "", err
		}

		s.logger.Info("Created new IP discovery",
			zap.String("discovery_id", ipDiscoveryID),
			zap.String("ip", finding.IP),
		)
		return ipDiscoveryID, nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing IP discovery",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return "", err
	}

	// IP exists - update last_seen and add scan_id to array
	update := bson.M{
		"$set": bson.M{
			"last_seen": timestamp,
		},
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
		return "", err
	}

	s.logger.Debug("Updated existing IP discovery",
		zap.String("discovery_id", existingIPDiscovery.ID),
		zap.String("ip", finding.IP),
	)
	return existingIPDiscovery.ID, nil
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
			Source:         finding.Source,
			Status:         finding.Status,
			OrgAssetStatus: shared.OrgAssetStatusConfirmed,     // Default to confirmed
			AssignedAt:     timestamp,                          // When assigned to org
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
		"org_asset_status": discovery.OrgAssetStatus,
		"assigned_at":      discovery.AssignedAt,
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
