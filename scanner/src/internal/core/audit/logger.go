package audit

import (
	"context"
	"time"

	"github.com/VulWall/VulWall/scanner/src/internal/core/redisx"
	"github.com/VulWall/VulWall/scanner/src/internal/core/telemetry"
	"github.com/VulWall/VulWall/scanner/src/internal/shared"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

// Logger provides a simplified interface for publishing system audit events
type Logger struct {
	redis       *redis.Client
	logger      *zap.Logger
	serviceName string
}

// NewLogger creates a new audit logger for a service
func NewLogger(redisClient *redis.Client, logger *zap.Logger, serviceName string) *Logger {
	return &Logger{
		redis:       redisClient,
		logger:      logger,
		serviceName: serviceName,
	}
}

// LogSuccess logs a successful operation
func (l *Logger) LogSuccess(ctx context.Context, category, action string, additionalInfo map[string]interface{}) {
	l.log(ctx, category, action, true, nil, additionalInfo)
}

// LogFailure logs a failed operation
func (l *Logger) LogFailure(ctx context.Context, category, action string, err error, additionalInfo map[string]interface{}) {
	l.log(ctx, category, action, false, err, additionalInfo)
}

// LogOperation logs an operation result (success or failure based on error)
// If err is nil, logs as success; otherwise logs as failure with the error
func (l *Logger) LogOperation(ctx context.Context, category, successAction, failureAction string, err error, additionalInfo map[string]interface{}) {
	if err == nil {
		l.log(ctx, category, successAction, true, nil, additionalInfo)
	} else {
		l.log(ctx, category, failureAction, false, err, additionalInfo)
	}
}

// log is the internal method that handles audit event creation and publishing
func (l *Logger) log(ctx context.Context, category, action string, success bool, err error, additionalInfo map[string]interface{}) {
	// Ensure additionalInfo map exists
	if additionalInfo == nil {
		additionalInfo = make(map[string]interface{})
	}

	// Add error to additional info if present
	if err != nil {
		additionalInfo["error"] = err.Error()
	}

	// Build audit event
	event := shared.SystemAuditEvent{
		Category:       category,
		Action:         action,
		Service:        l.serviceName,
		Success:        success,
		AdditionalInfo: additionalInfo,
		Timestamp:      time.Now(),
	}

	// Inject trace context for distributed tracing
	event.TraceContext = telemetry.InjectTraceContext(ctx)

	// Log to structured logger
	if success {
		l.logger.Info("Audit: "+action,
			zap.String("category", category),
			zap.Any("additional_info", additionalInfo),
		)
	} else {
		l.logger.Error("Audit: "+action,
			zap.String("category", category),
			zap.Error(err),
			zap.Any("additional_info", additionalInfo),
		)

		// Record error on span if available
		span := trace.SpanFromContext(ctx)
		if span.SpanContext().IsValid() && err != nil {
			span.RecordError(err)
		}
	}

	// Publish to Redis stream (keep last 1000 entries - audit events are infrequent)
	if publishErr := redisx.PublishToStream(ctx, l.redis, shared.StreamSystemAuditLogs, event, 1000); publishErr != nil {
		l.logger.Error("Failed to publish audit event",
			zap.String("category", category),
			zap.String("action", action),
			zap.Error(publishErr),
		)
	}
}
