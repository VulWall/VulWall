package ingestion

import (
	"context"
	"fmt"
	"sync"

	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/domain_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/enrichment_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/findings_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/kb_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion/port_ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// Orchestrator manages multiple ingestion consumers running concurrently
type Orchestrator struct {
	redis  *redis.Client
	db     *mongo.Database
	logger *zap.Logger
}

// NewOrchestrator creates a new ingestion orchestrator
func NewOrchestrator(redisClient *redis.Client, db *mongo.Database, logger *zap.Logger) *Orchestrator {
	return &Orchestrator{
		redis:  redisClient,
		db:     db,
		logger: logger,
	}
}

// Start launches all ingestion consumers concurrently
func (o *Orchestrator) Start(ctx context.Context) error {
	o.logger.Info("Starting ingestion orchestrator")

	// Shared activity tracker for scan idle detection.
	// All scan-scoped ingestion consumers share a single tracker instance
	// so throttle state is global (one write per scan per interval, not per consumer).
	activity := shared.NewScanActivityTracker(o.db, o.logger)

	// Shared org-existence guard. An org can be deleted mid-scan (Admin/Dashboard
	// cascade delete) while its pipeline is still in flight; the guard lets each
	// write path drop results for orgs that no longer exist instead of recreating
	// orphan documents. A single shared instance keeps the negative cache global.
	orgGuard := shared.NewOrgGuard(o.db, o.logger)
	// Shared asset guard: domain and port ingestion drop results of an asset that was
	// deleted, or whose delete has started, while its scan was in flight.
	assetGuard := shared.NewAssetGuard(o.db, o.logger)

	// Create wait group to manage goroutines
	var wg sync.WaitGroup
	errChan := make(chan error, 5) // Buffer for 5 consumers

	// Start domain ingestion consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.logger.Info("Starting domain ingestion consumer")

		domainConsumer := domain_ingestion.NewConsumer(o.redis, o.db, o.logger, activity, orgGuard, assetGuard)
		if err := domainConsumer.Start(ctx); err != nil && err != context.Canceled {
			o.logger.Error("Domain ingestion consumer failed", zap.Error(err))
			errChan <- fmt.Errorf("domain ingestion: %w", err)
		}
	}()

	// Start port ingestion consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.logger.Info("Starting port ingestion consumer")

		portConsumer := port_ingestion.NewConsumer(o.redis, o.db, o.logger, activity, orgGuard, assetGuard)
		if err := portConsumer.Start(ctx); err != nil && err != context.Canceled {
			o.logger.Error("Port ingestion consumer failed", zap.Error(err))
			errChan <- fmt.Errorf("port ingestion: %w", err)
		}
	}()

	// Start findings ingestion consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.logger.Info("Starting findings ingestion consumer")

		findingsConsumer := findings_ingestion.NewConsumer(o.redis, o.db, o.logger, activity, orgGuard)
		if err := findingsConsumer.Start(ctx); err != nil && err != context.Canceled {
			o.logger.Error("Findings ingestion consumer failed", zap.Error(err))
			errChan <- fmt.Errorf("findings ingestion: %w", err)
		}
	}()

	// Start enrichment ingestion consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.logger.Info("Starting enrichment ingestion consumer")

		enrichmentConsumer := enrichment_ingestion.NewConsumer(o.redis, o.db, o.logger, activity)
		if err := enrichmentConsumer.Start(ctx); err != nil && err != context.Canceled {
			o.logger.Error("Enrichment ingestion consumer failed", zap.Error(err))
			errChan <- fmt.Errorf("enrichment ingestion: %w", err)
		}
	}()

	// Start KB ingestion consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.logger.Info("Starting KB ingestion consumer")

		kbConsumer := kb_ingestion.NewConsumer(o.redis, o.db, o.logger)
		if err := kbConsumer.Start(ctx); err != nil && err != context.Canceled {
			o.logger.Error("KB ingestion consumer failed", zap.Error(err))
			errChan <- fmt.Errorf("kb ingestion: %w", err)
		}
	}()

	// Wait for either all goroutines to finish or an error to occur
	go func() {
		wg.Wait()
		close(errChan)
	}()

	// Return the first error that occurs
	for err := range errChan {
		if err != nil {
			o.logger.Error("Ingestion consumer error", zap.Error(err))
			return err
		}
	}

	o.logger.Info("All ingestion consumers stopped")
	return nil
}
