package telemetry

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

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
		sdktrace.WithBatchTimeout(time.Duration(getDuration("OTEL_BSP_SCHEDULED_DELAY_MILLIS", 5000))*time.Millisecond),
		sdktrace.WithMaxQueueSize(getInt("OTEL_BSP_MAX_QUEUE_SIZE", 2048)),
		sdktrace.WithMaxExportBatchSize(getInt("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", 512)),
		sdktrace.WithExportTimeout(time.Duration(getDuration("OTEL_BSP_EXPORT_TIMEOUT_MILLIS", 30000))*time.Millisecond),
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
	samplerArg := os.Getenv("OTEL_TRACES_SAMPLER_ARG")

	switch samplerName {
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "probabilistic":
		ratio := parseFloat(samplerArg, 0.1)
		return sdktrace.TraceIDRatioBased(ratio)
	case "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "parentbased_probabilistic":
		ratio := parseFloat(samplerArg, 0.1)
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	default:
		// Default to parent-based always on for development
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
}

// getOTLPEndpoint returns the OTLP endpoint (Honeycomb by default)
func getOTLPEndpoint() string {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "api.honeycomb.io"
	}
	return endpoint
}

// getHoneycombAPIKey returns the Honeycomb API key
func getHoneycombAPIKey() string {
	return os.Getenv("HONEYCOMB_API_KEY")
}

// getSamplerName returns the sampler name from environment
func getSamplerName() string {
	sampler := os.Getenv("OTEL_TRACES_SAMPLER")
	if sampler == "" {
		sampler = "parentbased_always_on"
	}
	return sampler
}

// isTracingEnabled returns true if tracing is enabled
func isTracingEnabled() bool {
	enabled := os.Getenv("OTEL_ENABLED")
	return enabled != "false" && enabled != "0"
}

// getInt returns an integer from environment or default value
func getInt(key string, defaultValue int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultValue
}

// getDuration returns a duration from environment or default value
func getDuration(key string, defaultMs int64) int64 {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return defaultMs
}

// parseFloat returns a float from string or default value
func parseFloat(val string, defaultValue float64) float64 {
	if val == "" {
		return defaultValue
	}
	if f, err := strconv.ParseFloat(val, 64); err == nil {
		return f
	}
	return defaultValue
}
