// Command nightwatch runs the whole VulWall scanner in one process: the scan
// coordinator, every discovery and active-recon consumer, the optional
// knowledge-base engine and the ingestion orchestrator (the only MongoDB
// writer). Components still talk to each other over Redis streams, exactly as
// they did when each ran as its own service.
//
// Usage:
//
//	nightwatch              run the scanner until SIGINT/SIGTERM
//	nightwatch healthcheck  exit 0 when Redis and MongoDB answer a ping
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/certificate_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/discovery_enrichment"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/email_security_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/http_header_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/js_dependency_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/nuclei_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/active_recon/testssl_scanner"
	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"github.com/VulWall/VulWall/scanner/src/internal/core/logger"
	"github.com/VulWall/VulWall/scanner/src/internal/core/mongox"
	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/sysinfo"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/discoveries/domain_discovery"
	"github.com/VulWall/VulWall/scanner/src/internal/discoveries/port_discovery"
	"github.com/VulWall/VulWall/scanner/src/internal/enrichers/knowledge_base"
	"github.com/VulWall/VulWall/scanner/src/internal/enrichers/knowledge_base/anthropic"
	"github.com/VulWall/VulWall/scanner/src/internal/ingestion"
	"github.com/VulWall/VulWall/scanner/src/internal/scan_coordinator"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"
)

// serviceName is the default OpenTelemetry service.name (OTEL_SERVICE_NAME overrides it).
const serviceName = "vulwall-scanner"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "nightwatch:", err)
		os.Exit(1)
	}
}

// component is one long-running part of the scanner.
type component struct {
	name  string
	start func(ctx context.Context) error
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if err := logger.Init(cfg.Environment); err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync()
	log := logger.Log

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("Starting VulWall scanner", zap.String("environment", cfg.Environment), zap.String("mongo_db", cfg.MongoDB))

	tp, err := telemetry.InitTracing(ctx, serviceName, cfg.Environment, log)
	if err != nil {
		log.Warn("Tracing disabled: failed to initialize", zap.Error(err))
	} else {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := tp.Shutdown(shutdownCtx); err != nil {
				log.Warn("Failed to flush traces", zap.Error(err))
			}
		}()
	}

	rdb, err := redisx.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("connect to Redis: %w", err)
	}
	defer rdb.Close()

	db, err := mongox.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("connect to MongoDB: %w", err)
	}
	defer func() {
		disconnectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = db.Client().Disconnect(disconnectCtx)
	}()

	if err := mongox.EnsureIndexes(ctx, db, log); err != nil {
		return fmt.Errorf("ensure indexes: %w", err)
	}

	// Create every consumer group before any component runs. Trigger-stream
	// groups start at "$", so a trigger published before its group exists
	// would never reach that scanner. Creating them here (idempotent) closes
	// that gap for a scan claimed in the first seconds after boot.
	if err := createConsumerGroups(ctx, rdb, log); err != nil {
		return err
	}

	workers, err := consumers(rdb, db, log)
	if err != nil {
		return err
	}
	coordinator, err := coordinatorComponents(ctx, rdb, db, log)
	if err != nil {
		return err
	}

	systemInfo := component{"system-info", func(ctx context.Context) error {
		return sysinfo.Run(ctx, db, sysinfo.DefaultSources(), log.With(zap.String("component", "system-info")))
	}}

	return supervise(ctx, log, append(append(workers, coordinator...), systemInfo))
}

// createConsumerGroups creates the groups of the discovery job queues (from
// "0") and of the trigger streams (from "$").
func createConsumerGroups(ctx context.Context, rdb *redis.Client, log *zap.Logger) error {
	if err := domain_discovery.DropLegacyGroup(ctx, rdb, log); err != nil {
		return err
	}
	jobQueues := []struct{ stream, group string }{
		{shared.StreamDomainDiscoveryQueue, domain_discovery.GroupDomainDiscovery},
		{shared.StreamIPDiscoveryQueue, port_discovery.GroupPortDiscovery},
	}
	for _, q := range jobQueues {
		if err := redisx.CreateConsumerGroup(ctx, rdb, q.stream, q.group); err != nil {
			return fmt.Errorf("create consumer group %s/%s: %w", q.stream, q.group, err)
		}
	}

	triggers := []struct{ stream, group string }{
		{shared.StreamDomainScanTriggers, nuclei_scanner.GroupNucleiScanner},
		{shared.StreamDomainScanTriggers, testssl_scanner.GroupTestSSLScanner},
		{shared.StreamDomainScanTriggers, js_dependency_scanner.GroupJSDependencyScanner},
		{shared.StreamDomainScanTriggers, http_header_scanner.GroupHTTPHeaderScanner},
		{shared.StreamDomainScanTriggers, email_security_scanner.GroupEmailSecurityScanner},
		{shared.StreamDomainScanTriggers, certificate_scanner.GroupCertificateScanner},
		{shared.StreamPortScanTriggers, nuclei_scanner.GroupNucleiScanner},
		{shared.StreamPortScanTriggers, certificate_scanner.GroupCertificateScanner},
	}
	for _, t := range triggers {
		if err := redisx.CreateConsumerGroupFromLatest(ctx, rdb, t.stream, t.group); err != nil {
			return fmt.Errorf("create consumer group %s/%s: %w", t.stream, t.group, err)
		}
	}
	return nil
}

// consumers builds the stream consumers and the ingestion orchestrator.
func consumers(rdb *redis.Client, db *mongo.Database, log *zap.Logger) ([]component, error) {
	named := func(name string) *zap.Logger { return log.With(zap.String("component", name)) }

	domainDiscovery, err := domain_discovery.NewConsumer(rdb, named("domain-discovery"))
	if err != nil {
		return nil, fmt.Errorf("domain-discovery: %w", err)
	}
	jsDeps, err := js_dependency_scanner.NewConsumer(rdb, named("js-dependency-scanner"))
	if err != nil {
		return nil, fmt.Errorf("js-dependency-scanner: %w", err)
	}
	headers, err := http_header_scanner.NewConsumer(rdb, named("http-header-scanner"))
	if err != nil {
		return nil, fmt.Errorf("http-header-scanner: %w", err)
	}
	email, err := email_security_scanner.NewConsumer(rdb, named("email-security-scanner"))
	if err != nil {
		return nil, fmt.Errorf("email-security-scanner: %w", err)
	}
	enrichment, err := discovery_enrichment.NewConsumer(rdb, named("discovery-enrichment"))
	if err != nil {
		return nil, fmt.Errorf("discovery-enrichment: %w", err)
	}

	list := []component{
		{"domain-discovery", domainDiscovery.Start},
		{"port-discovery", port_discovery.NewConsumer(rdb, named("port-discovery")).Start},
		{"nuclei-scanner", nuclei_scanner.NewConsumer(rdb, named("nuclei-scanner")).Start},
		{"testssl-scanner", testssl_scanner.NewConsumer(rdb, named("testssl-scanner")).Start},
		{"certificate-scanner", certificate_scanner.NewConsumer(rdb, named("certificate-scanner")).Start},
		{"js-dependency-scanner", jsDeps.Start},
		{"http-header-scanner", headers.Start},
		{"email-security-scanner", email.Start},
		{"discovery-enrichment", enrichment.Start},
		{"ingestion", ingestion.NewOrchestrator(rdb, db, named("ingestion")).Start},
	}

	kb, err := knowledgeBase(rdb, named("knowledge-base-engine"))
	if err != nil {
		return nil, fmt.Errorf("knowledge-base-engine: %w", err)
	}
	if kb != nil {
		list = append(list, *kb)
	}
	return list, nil
}

// knowledgeBase returns the KB engine, or nil when ANTHROPIC_API_KEY is not
// set. Without it, kb_generation_queue keeps its jobs; they are processed
// once the key is configured and the scanner restarts.
func knowledgeBase(rdb *redis.Client, log *zap.Logger) (*component, error) {
	apiKey := config.GetEnv(config.EnvAnthropicAPIKey, "")
	if apiKey == "" {
		log.Info("ANTHROPIC_API_KEY is not set: AI knowledge-base generation is disabled. Findings keep the scanners' own descriptions.")
		return nil, nil
	}
	model := config.GetEnv(config.EnvAnthropicModel, anthropic.DefaultModel)
	service, err := knowledge_base.NewService(rdb, anthropic.NewClient(apiKey, model, log), log)
	if err != nil {
		return nil, err
	}
	return &component{"knowledge-base-engine", knowledge_base.NewConsumer(rdb, service, log).Start}, nil
}

// coordinatorComponents builds the scan coordinator: cron scheduler (with
// stream cleanup), queued-scan poller and scan monitor. It first closes scans
// that a previous run left pending or running, before the monitor could
// finish them from partial results.
func coordinatorComponents(ctx context.Context, rdb *redis.Client, db *mongo.Database, log *zap.Logger) ([]component, error) {
	log = log.With(zap.String("component", "scan-coordinator"))
	service := scan_coordinator.NewService(rdb, db, log)
	if _, err := service.CloseInterruptedScans(ctx); err != nil {
		return nil, err
	}
	// Runs before supervise starts any consumer, so every consumer it removes belongs to
	// the previous process.
	if err := scan_coordinator.ReleaseOrphanedPending(ctx, rdb, log); err != nil {
		return nil, err
	}
	scheduler := scan_coordinator.NewScheduler(service, db, scan_coordinator.NewStreamCleaner(rdb, log), log)
	monitor := scan_coordinator.NewScanMonitor(rdb, db, log)

	return []component{
		{"scheduler", scheduler.Start},
		{"queued-scan-poller", func(ctx context.Context) error { service.StartQueuedScans(ctx); return nil }},
		{"scan-monitor", func(ctx context.Context) error { monitor.Start(ctx); return nil }},
	}, nil
}

// supervise runs all components until ctx is cancelled or one of them fails.
// A failing component cancels the others, and the process exits non-zero so
// the container restart policy brings the whole scanner back.
func supervise(ctx context.Context, log *zap.Logger, components []component) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg       sync.WaitGroup
		once     sync.Once
		firstErr error
	)
	for _, c := range components {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.start(ctx)
			if err == nil || errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return
			}
			once.Do(func() {
				firstErr = fmt.Errorf("%s: %w", c.name, err)
				log.Error("Component failed; shutting down", zap.String("component", c.name), zap.Error(err))
				cancel()
			})
		}()
	}
	log.Info("Scanner running", zap.Int("components", len(components)))

	<-ctx.Done()
	if firstErr == nil {
		log.Info("Shutdown signal received; stopping components")
	}
	wg.Wait()
	log.Info("Scanner stopped")
	return firstErr
}

// healthcheck pings Redis and MongoDB with the same configuration as the
// scanner. Used by the container HEALTHCHECK; it opens no port.
func healthcheck() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy: config:", err)
		return 1
	}
	rdb, err := redisx.NewClient(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy: redis:", err)
		return 1
	}
	defer rdb.Close()
	db, err := mongox.NewClient(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy: mongodb:", err)
		return 1
	}
	_ = db.Client().Disconnect(context.Background())
	return 0
}
