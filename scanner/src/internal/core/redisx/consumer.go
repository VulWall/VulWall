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
//
// A returned error means "not done": the consumer loop runs the handler again
// (see processMessage). Wrap an error with Permanent when a retry cannot help
// (a malformed message), so the message is dead-lettered at once.
type MessageHandler func(ctx context.Context, message redis.XMessage) error

// permanent marks a handler error that a retry cannot fix.
type permanent struct{ err error }

func (p *permanent) Error() string { return p.err.Error() }
func (p *permanent) Unwrap() error { return p.err }

// Permanent wraps err so the consumer loop dead-letters the message without a retry.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanent{err: err}
}

// IsPermanent reports whether err was wrapped with Permanent.
func IsPermanent(err error) bool {
	var p *permanent
	return errors.As(err, &p)
}

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

// handlerAttempts is how many times a message is handled before it is dead-lettered, and
// handlerRetryDelay the base of the linear backoff between attempts. The retries run in the
// worker, so the message stays pending (and the scan stays open) while they run. Variables so
// tests can shorten them.
var (
	handlerAttempts   = 3
	handlerRetryDelay = 2 * time.Second
)

// pendingHeartbeat is how often a message whose handler is still running has its pending
// entry's idle time reset (keepPendingFresh). A variable so tests can shorten it.
var pendingHeartbeat = time.Minute

// ackTimeout bounds an ACK sent with a context detached from shutdown.
const ackTimeout = 5 * time.Second

// ConsumeStream runs a blocking consumer loop that reads messages from a Redis
// stream and dispatches them to handler workers. It handles:
//   - Unique consumer name generation (prefix + UUID)
//   - Worker pool for concurrent processing
//   - Message ACK after the handler succeeds
//   - A handler error is retried in the worker (handlerAttempts in all); a
//     message that still fails, or a Permanent error, is dead-lettered and then
//     ACKed, so no message is redelivered forever
//   - A handler panic is recovered, logged with its stack, dead-lettered and
//     ACKed, so one poisoned message cannot crash the scanner or loop
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
			deadLetter := func(ctx context.Context, message redis.XMessage, cause error) error {
				data, _ := message.Values["data"].(string)
				return PublishDeadLetter(ctx, client, cfg.Stream, cfg.Group, message.ID, data, cause)
			}
			for message := range jobs {
				stop := keepPendingFresh(ctx, client, cfg.Stream, cfg.Group, consumerName, message.ID, log)
				processMessage(ctx, cfg.Handler, ack, deadLetter, log, message)
				stop()
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

// keepPendingFresh resets the idle time of message id's pending entry every pendingHeartbeat
// until the returned stop is called, so the entry of a handler that is still running (a nuclei
// run can take over an hour) stays young. The scan monitor reads a young pending entry as
// work in flight and an old one as stuck (scan_coordinator.freshPendingWork); without the
// heartbeat a long run looks stuck and the idle timeout closes the scan under it.
//
// XCLAIM to the same consumer with min-idle 0 and JUSTID resets the idle time and does not
// count as a delivery. An entry already ACKed is not claimed, so a late beat is harmless.
func keepPendingFresh(ctx context.Context, client *redis.Client, stream, group, consumer, id string, logger *zap.Logger) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ticker := time.NewTicker(pendingHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := client.XClaimJustID(ctx, &redis.XClaimArgs{
					Stream: stream, Group: group, Consumer: consumer, MinIdle: 0, Messages: []string{id},
				}).Err()
				if err != nil && ctx.Err() == nil {
					logger.Warn("Failed to refresh pending entry", zap.String("message_id", id), zap.Error(err))
				}
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

// processMessage runs the handler for one message and decides whether to ACK it.
//
//   - Success: ACK.
//   - Handler error: run the handler again, up to handlerAttempts times in all, with a
//     growing delay. The message stays pending meanwhile. A Permanent error is not
//     retried. When the attempts run out, dead-letter the message, then ACK it.
//   - Handler panic: recover, log with the stack, dead-letter, ACK. A panic is a bug in
//     the handler, so a retry would panic again.
//   - Shutdown (ctx cancelled) while the handler fails or between attempts: do not ACK.
//     The work was cut off, not finished, so the message must stay pending.
//
// The ACK and the dead-letter use a context detached from ctx, so a handler that finished
// just as shutdown began is still ACKed.
func processMessage(ctx context.Context, handler MessageHandler, ack func(context.Context, string) error,
	deadLetter func(context.Context, redis.XMessage, error) error, logger *zap.Logger, message redis.XMessage) {
	var err error
	for attempt := 1; ; attempt++ {
		err = runHandler(ctx, handler, message)
		var panicErr *handlerPanic
		switch {
		case err == nil:
		case errors.As(err, &panicErr):
			logger.Error("Message handler panicked; dead-lettering the message so it is not redelivered",
				zap.String("message_id", message.ID),
				zap.Any("panic", panicErr.value),
				zap.String("stack", panicErr.stack),
			)
		case ctx.Err() != nil:
			logger.Info("Message handler stopped by shutdown; leaving the message unACKed",
				zap.String("message_id", message.ID),
				zap.Error(err),
			)
			return
		case IsPermanent(err) || attempt >= handlerAttempts:
			logger.Error("Message failed for good; dead-lettering it",
				zap.String("message_id", message.ID),
				zap.Int("attempts", attempt),
				zap.Error(err),
			)
		default:
			logger.Warn("Message handler failed; retrying",
				zap.String("message_id", message.ID),
				zap.Int("attempt", attempt),
				zap.Error(err),
			)
			select {
			case <-ctx.Done():
				logger.Info("Shutdown before a retry; leaving the message unACKed",
					zap.String("message_id", message.ID))
				return
			case <-time.After(time.Duration(attempt) * handlerRetryDelay):
			}
			continue
		}
		break
	}

	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), ackTimeout)
	defer cancel()
	if err != nil {
		if dlErr := deadLetter(detached, message, err); dlErr != nil {
			logger.Warn("Failed to dead-letter message", zap.String("message_id", message.ID), zap.Error(dlErr))
		}
	}
	if err := ack(detached, message.ID); err != nil {
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
