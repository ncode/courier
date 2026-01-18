package auditserver

import (
	"log/slog"
	"os"
	"runtime"
	"sync"
)

// UpdateKind identifies the type of Vault object being synchronized.
type UpdateKind string

const (
	UpdateKindKV     UpdateKind = "kv"
	UpdateKindPolicy UpdateKind = "policy"
)

type UpdateEvent struct {
	Kind      UpdateKind
	Path      string
	Operation string
}

// SyncHandler runs the downstream synchronization for a given update event.
type SyncHandler func(event UpdateEvent) error

// Dispatcher maintains a deduplicated set of in-flight paths and delivers work to in-process workers.
type Dispatcher struct {
	mu         sync.Mutex
	pending    map[string]struct{}
	logger     *slog.Logger
	queue      chan UpdateEvent
	deadLetter []UpdateEvent
	handler    SyncHandler
}

// NewDispatcher constructs a dispatcher with the provided handler and starts worker goroutines.
// queueSize controls backpressure; concurrency controls worker count. Defaults are applied when <= 0.
func NewDispatcher(logger *slog.Logger, handler SyncHandler, queueSize int, concurrency int) *Dispatcher {
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if handler == nil {
		handler = func(UpdateEvent) error { return nil }
	}
	if queueSize <= 0 {
		queueSize = 64
	}
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}

	d := &Dispatcher{
		pending: make(map[string]struct{}),
		logger:  logger,
		queue:   make(chan UpdateEvent, queueSize),
		handler: handler,
	}

	for i := 0; i < concurrency; i++ {
		go d.worker()
	}

	return d
}

// Enqueue adds a path to the pending set if not already present and submits it to workers via the queue.
func (d *Dispatcher) Enqueue(event UpdateEvent) {
	key := d.key(event.Kind, event.Path)

	d.mu.Lock()
	if _, exists := d.pending[key]; exists {
		d.logger.Info("Skipping duplicate pending update", "kind", event.Kind, "path", event.Path)
		d.mu.Unlock()
		return
	}
	d.pending[key] = struct{}{}
	d.logger.Info("Enqueued update", "kind", event.Kind, "path", event.Path, "operation", event.Operation)
	d.mu.Unlock()

	select {
	case d.queue <- event:
	default:
		d.logger.Error("Queue full, sending to dead letter", "kind", event.Kind, "path", event.Path)
		d.mu.Lock()
		delete(d.pending, key)
		d.deadLetter = append(d.deadLetter, event)
		d.mu.Unlock()
	}
}

func (d *Dispatcher) worker() {
	for event := range d.queue {
		if err := d.handler(event); err != nil {
			d.logger.Error("Sync failed", "kind", event.Kind, "path", event.Path, "operation", event.Operation, "error", err)
		} else {
			d.logger.Info("Sync completed", "kind", event.Kind, "path", event.Path, "operation", event.Operation)
		}

		d.mu.Lock()
		delete(d.pending, d.key(event.Kind, event.Path))
		d.mu.Unlock()
	}
}

func (d *Dispatcher) key(kind UpdateKind, path string) string {
	return string(kind) + ":" + path
}
