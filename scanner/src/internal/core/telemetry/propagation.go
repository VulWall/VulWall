package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// TraceContext holds W3C TraceContext propagation headers
// This is used to propagate trace context across service boundaries via Redis streams
type TraceContext map[string]string

// InjectTraceContext injects the current span context into a TraceContext map
// This should be called by publishers before sending messages to Redis streams
func InjectTraceContext(ctx context.Context) TraceContext {
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	return TraceContext(carrier)
}

// ExtractTraceContext extracts trace context from a TraceContext map and returns a new context
// This should be called by consumers after receiving messages from Redis streams
func ExtractTraceContext(ctx context.Context, tc TraceContext) context.Context {
	if tc == nil {
		return ctx
	}
	carrier := propagation.MapCarrier(tc)
	return otel.GetTextMapPropagator().Extract(ctx, carrier)
}
