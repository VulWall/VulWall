package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/config"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap"
)

type TracerProvider struct {
	tp *sdktrace.TracerProvider
}

// InitTracing initializes OpenTelemetry with Honeycomb OTLP exporter
func InitTracing(ctx context.Context, serviceName, environment string, logger *zap.Logger) (*TracerProvider, error) {
	if !isTracingEnabled() {
		logger.Info("OpenTelemetry tracing is disabled")
		return &TracerProvider{tp: sdktrace.NewTracerProvider()}, nil
	}

	logger.Info("Initializing OpenTelemetry tracing",
		zap.String("service", serviceName),
		zap.String("environment", environment),
	)

	// Create OTLP HTTP exporter for Honeycomb
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(getOTLPEndpoint()),
		otlptracehttp.WithURLPath("/v1/traces"), // Honeycomb requires this path
		otlptracehttp.WithHeaders(map[string]string{
			"x-honeycomb-team": getHoneycombAPIKey(),
		}),
		otlptracehttp.WithTimeout(30*time.Second),
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource describing the service
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.DeploymentEnvironmentKey.String(environment),
			attribute.String("service.namespace", "vulwall"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create batch processor for efficient span export
	bsp := sdktrace.NewBatchSpanProcessor(exporter,
		sdktrace.WithBatchTimeout(time.Duration(config.GetEnvInt64(config.EnvOTELBSPScheduledDelay, 5000))*time.Millisecond),
		sdktrace.WithMaxQueueSize(config.GetEnvInt(config.EnvOTELBSPMaxQueueSize, 2048)),
		sdktrace.WithMaxExportBatchSize(config.GetEnvInt(config.EnvOTELBSPMaxExportBatch, 512)),
		sdktrace.WithExportTimeout(time.Duration(config.GetEnvInt64(config.EnvOTELBSPExportTimeout, 30000))*time.Millisecond),
	)

	// Create TracerProvider with sampler
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithSampler(buildSampler()),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)

	// Set text map propagator for W3C Trace Context
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("OpenTelemetry initialized successfully",
		zap.String("endpoint", getOTLPEndpoint()),
		zap.String("sampler", getSamplerName()),
	)

	return &TracerProvider{tp: tp}, nil
}

// Shutdown gracefully shuts down the tracer provider
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.tp == nil {
		return nil
	}
	return tp.tp.Shutdown(ctx)
}

// buildSampler creates the appropriate sampler based on environment
func buildSampler() sdktrace.Sampler {
	samplerName := getSamplerName()

	switch samplerName {
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "probabilistic":
		ratio := config.GetEnvFloat64(config.EnvOTELTraceSamplerArg, 0.1)
		return sdktrace.TraceIDRatioBased(ratio)
	case "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "parentbased_probabilistic":
		ratio := config.GetEnvFloat64(config.EnvOTELTraceSamplerArg, 0.1)
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	default:
		// Default to parent-based always on for development
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
}

// getOTLPEndpoint returns the OTLP endpoint (Honeycomb by default)
func getOTLPEndpoint() string {
	return config.GetEnv(config.EnvOTELExporterEndpoint, "api.honeycomb.io")
}

// getHoneycombAPIKey returns the Honeycomb API key
func getHoneycombAPIKey() string {
	return config.GetEnv(config.EnvHoneycombAPIKey, "")
}

// getSamplerName returns the sampler name from environment
func getSamplerName() string {
	return config.GetEnv(config.EnvOTELTraceSampler, "parentbased_always_on")
}

// isTracingEnabled returns true if tracing is enabled
func isTracingEnabled() bool {
	enabled := config.GetEnv(config.EnvOTELEnabled, "")
	return enabled != "false" && enabled != "0"
}
