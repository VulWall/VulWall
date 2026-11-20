package redisx

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// MessageHandler processes a single Redis stream message.
// The handler is responsible for its own business logic only.
// ACK is handled by the consumer loop after the handler returns.
type MessageHandler func(ctx context.Context, message redis.XMessage) error

// ConsumerConfig configures a stream consumer loop.
type ConsumerConfig struct {
	// Stream is the Redis stream name to consume from.
	Stream string

	// Group is the consumer group name.
	Group string

	// ConsumerPrefix is the prefix for the auto-generated consumer name.
	// A UUID suffix is appended automatically (e.g., "nuclei-domain-<uuid>").
	ConsumerPrefix string

	// BatchSize is the number of messages to read per XReadGroup call.
	// Defaults to 1 if not set.
	BatchSize int64

	// Concurrency is the number of worker goroutines processing messages.
	// Defaults to 1 if not set. When > 1, a buffered channel dispatches
	// messages to workers. Each worker calls Handler then ACKs.
	Concurrency int

	// BlockDuration is how long XReadGroup blocks waiting for new messages.
	// Defaults to 5s if zero. Set to 0 explicitly via a sentinel if you
	// want indefinite blocking (not recommended -- use 5s).
	BlockDuration time.Duration

	// Handler processes a single message. Required.
	Handler MessageHandler

	// Logger for structured logging. Required.
	Logger *zap.Logger
}

const defaultBlockDuration = 5 * time.Second
const errorBackoff = 5 * time.Second

// ackTimeout bounds an ACK sent with a context detached from shutdown.
const ackTimeout = 5 * time.Second

// ConsumeStream runs a blocking consumer loop that reads messages from a Redis
// stream and dispatches them to handler workers. It handles:
//   - Unique consumer name generation (prefix + UUID)
//   - Worker pool for concurrent processing
//   - Message ACK after handler returns (ACKs on success and on handler error)
//   - A handler panic is recovered, logged with its stack and ACKed, so one
//     poisoned message cannot crash the scanner or be retried forever
//   - Graceful shutdown on context cancellation: a handler that fails because
//     ctx was cancelled is not ACKed, so the message stays pending
//     (see processMessage)
//
// The caller is responsible for consumer group creation and stale consumer
// cleanup before calling this function. This keeps ConsumeStream focused on
// a single responsibility: the read-dispatch-ack loop.
//
// Returns ctx.Err() on context cancellation (normal shutdown).
func ConsumeStream(ctx context.Context, client *redis.Client, cfg ConsumerConfig) error {
	// Apply defaults
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 1
	}
	if cfg.BlockDuration == 0 {
		cfg.BlockDuration = defaultBlockDuration
	}

	consumerName := cfg.ConsumerPrefix + "-" + uuid.New().String()

	cfg.Logger.Info("Starting stream consumer",
		zap.String("stream", cfg.Stream),
		zap.String("group", cfg.Group),
		zap.String("consumer", consumerName),
		zap.Int("concurrency", cfg.Concurrency),
		zap.Int64("batch_size", cfg.BatchSize),
	)

	// Worker pool: buffered channel sized to concurrency so the read loop
	// does not block on dispatch unless all workers are busy.
	jobs := make(chan redis.XMessage, cfg.Concurrency)
	var wg sync.WaitGroup

	for i := range cfg.Concurrency {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			log := cfg.Logger.With(zap.Int("worker", workerID))
			ack := func(ctx context.Context, id string) error {
				return client.XAck(ctx, cfg.Stream, cfg.Group, id).Err()
			}
			for message := range jobs {
				processMessage(ctx, cfg.Handler, ack, log, message)
			}
		}(i)
	}

	// Ensure workers drain before returning.
	defer func() {
		close(jobs)
		wg.Wait()
	}()

	// Read loop
	for {
		select {
		case <-ctx.Done():
			cfg.Logger.Info("Consumer shutting down", zap.String("stream", cfg.Stream))
			return ctx.Err()
		default:
			streams, err := client.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    cfg.Group,
				Consumer: consumerName,
				Streams:  []string{cfg.Stream, ">"},
				Count:    cfg.BatchSize,
				Block:    cfg.BlockDuration,
			}).Result()

			if err != nil {
				if err == redis.Nil {
					continue
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				cfg.Logger.Error("Failed to read from stream",
					zap.String("stream", cfg.Stream),
					zap.Error(err),
				)
				// Back off before retrying to avoid tight error loops.
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(errorBackoff):
				}
				continue
			}

			for _, stream := range streams {
				for _, message := range stream.Messages {
					select {
					case jobs <- message:
					case <-ctx.Done():
						// Not dispatched: the message stays pending, unACKed.
						return ctx.Err()
					}
				}
			}
		}
	}
}

// processMessage runs the handler for one message and decides whether to ACK it.
//
//   - Success or handler error: ACK. Services that need selective ACK
//     (dead-letter, retry) handle it inside their handler and return nil.
//   - Handler panic: recover, log with the stack, ACK. Without the ACK a
//     poisoned message would crash or loop the consumer on every delivery.
//   - Handler error while ctx is cancelled: do not ACK. The work was cut off by
//     shutdown, not finished, so the message must stay pending.
//
// The ACK uses a context detached from ctx, so a handler that finished just as
// shutdown began is still ACKed.
func processMessage(ctx context.Context, handler MessageHandler, ack func(context.Context, string) error, logger *zap.Logger, message redis.XMessage) {
	err := runHandler(ctx, handler, message)

	var panicErr *handlerPanic
	switch {
	case errors.As(err, &panicErr):
		logger.Error("Message handler panicked; ACKing the message so it is not redelivered",
			zap.String("message_id", message.ID),
			zap.Any("panic", panicErr.value),
			zap.String("stack", panicErr.stack),
		)
	case err != nil && ctx.Err() != nil:
		logger.Warn("Message handler stopped by shutdown; leaving the message unACKed",
			zap.String("message_id", message.ID),
			zap.Error(err),
		)
		return
	case err != nil:
		logger.Error("Failed to process message",
			zap.String("message_id", message.ID),
			zap.Error(err),
		)
	}

	ackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ackTimeout)
	defer cancel()
	if err := ack(ackCtx, message.ID); err != nil {
		logger.Warn("Failed to ACK message", zap.String("message_id", message.ID), zap.Error(err))
	}
}

// handlerPanic carries a recovered handler panic and its stack.
type handlerPanic struct {
	value any
	stack string
}

func (p *handlerPanic) Error() string { return fmt.Sprintf("handler panic: %v", p.value) }

// runHandler calls handler and turns a panic into a *handlerPanic error.
func runHandler(ctx context.Context, handler MessageHandler, message redis.XMessage) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = &handlerPanic{value: r, stack: string(debug.Stack())}
		}
	}()
	return handler(ctx, message)
}
