package ingestion

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-redis/redis/v8"
	"github.com/vulwall/scanners/internal/ingestion/domain_ingestion"
	"github.com/vulwall/scanners/internal/ingestion/findings_ingestion"
	"github.com/vulwall/scanners/internal/ingestion/port_ingestion"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// Orchestrator manages multiple ingestion consumers running concurrently
type Orchestrator struct {
	redis              *redis.Client
	db                 *mongo.Database
	ipEnrichmentDBPath string
	logger             *zap.Logger
}

// NewOrchestrator creates a new ingestion orchestrator
func NewOrchestrator(redisClient *redis.Client, db *mongo.Database, ipEnrichmentDBPath string, logger *zap.Logger) *Orchestrator {
	return &Orchestrator{
		redis:              redisClient,
		db:                 db,
		ipEnrichmentDBPath: ipEnrichmentDBPath,
		logger:             logger,
	}
}

// Start launches all ingestion consumers concurrently
func (o *Orchestrator) Start(ctx context.Context) error {
	o.logger.Info("Starting ingestion orchestrator")

	// Create wait group to manage goroutines
	var wg sync.WaitGroup
	errChan := make(chan error, 3) // Buffer for 3 consumers

	// Start domain ingestion consumer
	wg.Add(1)
	go func() {
		defer wg.Done()
		o.logger.Info("Starting domain ingestion consumer")

		domainConsumer := domain_ingestion.NewConsumer(o.redis, o.db, o.ipEnrichmentDBPath, o.logger)
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

		portConsumer := port_ingestion.NewConsumer(o.redis, o.db, o.ipEnrichmentDBPath, o.logger)
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

		findingsConsumer := findings_ingestion.NewConsumer(o.redis, o.db, o.logger)
		if err := findingsConsumer.Start(ctx); err != nil && err != context.Canceled {
			o.logger.Error("Findings ingestion consumer failed", zap.Error(err))
			errChan <- fmt.Errorf("findings ingestion: %w", err)
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
