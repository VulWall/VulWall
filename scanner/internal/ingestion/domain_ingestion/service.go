package domain_ingestion

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vulwall/scanners/internal/shared"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

type Service struct {
	db     *mongo.Database
	logger *zap.Logger
}

func NewService(db *mongo.Database, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
	}
}

// ProcessFinding processes a domain discovery finding and persists it to MongoDB
func (s *Service) ProcessFinding(ctx context.Context, finding shared.DiscoveryFinding) error {
	s.logger.Info("Processing domain discovery finding",
		zap.String("trace_id", finding.TraceID),
		zap.String("org_id", finding.OrgID),
		zap.String("source", finding.Source),
		zap.String("host", finding.Host),
	)

	// Validate source is present (required) - skip if missing
	if finding.Source == "" {
		s.logger.Warn("Skipping finding: missing source",
			zap.String("trace_id", finding.TraceID),
			zap.String("org_id", finding.OrgID),
			zap.String("host", finding.Host),
		)
		return nil
	}

	// Handle Shodan discoveries - store in OrgDomains collection
	if finding.Source == "shodan" && finding.Port == nil && finding.IP != nil {
		return s.processOrgDomain(ctx, finding)
	}

	// Skip non-Shodan findings (attack surface ingestion removed from domain ingestion)
	s.logger.Debug("Skipping non-Shodan finding",
		zap.String("trace_id", finding.TraceID),
		zap.String("source", finding.Source),
		zap.String("host", finding.Host),
	)
	return nil
}

// processOrgDomain processes Shodan domain discoveries and stores them in OrgDomains collection
func (s *Service) processOrgDomain(ctx context.Context, finding shared.DiscoveryFinding) error {
	collection := s.db.Collection(shared.CollectionOrgDomains)
	now := time.Now()

	// Check if domain already exists for this org
	filter := bson.M{
		"org_id": finding.OrgID,
		"domain": finding.Host,
	}

	var existingDomain shared.OrgDomain
	err := collection.FindOne(ctx, filter).Decode(&existingDomain)

	if err == mongo.ErrNoDocuments {
		// Create new OrgDomain with first IP resolution
		newDomain := &shared.OrgDomain{
			ID:     uuid.New().String(),
			OrgID:  finding.OrgID,
			Domain: finding.Host,
			Source: finding.Source,
			ResolutionHistory: []shared.ResolutionHistory{
				{
					IP:            *finding.IP,
					ResolvedFrom:  now,
					ResolvedUntil: nil, // Currently active
				},
			},
		}

		doc := bson.M{
			"_id":                newDomain.ID,
			"org_id":             newDomain.OrgID,
			"domain":             newDomain.Domain,
			"source":             newDomain.Source,
			"resolution_history": newDomain.ResolutionHistory,
		}

		_, err := collection.InsertOne(ctx, doc)
		if err != nil {
			s.logger.Error("Failed to create OrgDomain",
				zap.String("domain", finding.Host),
				zap.String("org_id", finding.OrgID),
				zap.Error(err),
			)
			return err
		}

		s.logger.Info("Created new OrgDomain",
			zap.String("domain", finding.Host),
			zap.String("org_id", finding.OrgID),
			zap.String("ip", *finding.IP),
		)
		return nil
	}

	if err != nil {
		s.logger.Error("Failed to check existing OrgDomain",
			zap.String("trace_id", finding.TraceID),
			zap.Error(err),
		)
		return err
	}

	// Domain exists - check if IP has changed
	return s.updateOrgDomainResolution(ctx, &existingDomain, *finding.IP, now)
}

// updateOrgDomainResolution updates the resolution history when IP changes
func (s *Service) updateOrgDomainResolution(ctx context.Context, domain *shared.OrgDomain, newIP string, timestamp time.Time) error {
	collection := s.db.Collection(shared.CollectionOrgDomains)

	// Check if the most recent resolution is still active and matches the new IP
	if len(domain.ResolutionHistory) > 0 {
		lastResolution := domain.ResolutionHistory[len(domain.ResolutionHistory)-1]

		// If IP hasn't changed and resolution is still active, no update needed
		if lastResolution.IP == newIP && lastResolution.ResolvedUntil == nil {
			s.logger.Debug("IP unchanged, no update needed",
				zap.String("domain", domain.Domain),
				zap.String("ip", newIP),
			)
			return nil
		}

		// If IP has changed, close the current resolution and add new one
		if lastResolution.IP != newIP && lastResolution.ResolvedUntil == nil {
			// Close the previous resolution
			update := bson.M{
				"$set": bson.M{
					"resolution_history." + fmt.Sprint(len(domain.ResolutionHistory)-1) + ".resolved_until": timestamp,
				},
				"$push": bson.M{
					"resolution_history": shared.ResolutionHistory{
						IP:            newIP,
						ResolvedFrom:  timestamp,
						ResolvedUntil: nil, // Currently active
					},
				},
			}

			_, err := collection.UpdateOne(ctx, bson.M{"_id": domain.ID}, update)
			if err != nil {
				s.logger.Error("Failed to update OrgDomain resolution",
					zap.String("domain", domain.Domain),
					zap.Error(err),
				)
				return err
			}

			s.logger.Info("Updated OrgDomain with new IP resolution",
				zap.String("domain", domain.Domain),
				zap.String("old_ip", lastResolution.IP),
				zap.String("new_ip", newIP),
			)
			return nil
		}
	}

	// If we get here, add a new resolution (shouldn't normally happen, but handle it)
	update := bson.M{
		"$push": bson.M{
			"resolution_history": shared.ResolutionHistory{
				IP:            newIP,
				ResolvedFrom:  timestamp,
				ResolvedUntil: nil,
			},
		},
	}

	_, err := collection.UpdateOne(ctx, bson.M{"_id": domain.ID}, update)
	if err != nil {
		s.logger.Error("Failed to add resolution to OrgDomain",
			zap.String("domain", domain.Domain),
			zap.Error(err),
		)
		return err
	}

	s.logger.Info("Added new resolution to OrgDomain",
		zap.String("domain", domain.Domain),
		zap.String("ip", newIP),
	)
	return nil
}
