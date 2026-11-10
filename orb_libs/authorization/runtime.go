package authorization

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrNilSnapshotSource     = errors.New("snapshot source is required")
	ErrRuntimeAlreadyStarted = errors.New("runtime already started")
	ErrRuntimeStopped        = errors.New("cannot start stopped runtime")
)

// RuntimeConfig configures the authorization Runtime.
type RuntimeConfig struct {
	// PollInterval defines how often the runtime checks the database for policy updates.
	PollInterval time.Duration
	// RetryBackoff defines how long to wait before retrying after a failed sync.
	RetryBackoff time.Duration
	// MaxPolicyAge defines the maximum allowed staleness before the engine fails closed.
	MaxPolicyAge time.Duration
}

// DefaultRuntimeConfig returns production-ready defaults with explicit non-zero staleness enforcement.
func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		PollInterval: 5 * time.Second,
		RetryBackoff: 1 * time.Second,
		MaxPolicyAge: 30 * time.Minute,
	}
}

// Runtime is the single, reusable authorization coordinator for services.
// It coordinates the SnapshotHolder, local Engine, initial bootstrap, periodic background synchronization,
// freshness tracking, and graceful shutdown.
type Runtime struct {
	source SnapshotSource
	holder *SnapshotHolder
	engine *LocalEngine
	cfg    RuntimeConfig

	mu      sync.Mutex
	started bool
	stopped bool
	cancel  context.CancelFunc
	done    chan struct{}
	syncMu  sync.Mutex // serializes synchronization attempts
}

// NewRuntime creates and initializes a new Runtime backed by the provided SnapshotSource.
func NewRuntime(source SnapshotSource, cfg ...RuntimeConfig) (*Runtime, error) {
	if source == nil {
		return nil, ErrNilSnapshotSource
	}

	config := DefaultRuntimeConfig()
	if len(cfg) > 0 {
		if cfg[0].PollInterval > 0 {
			config.PollInterval = cfg[0].PollInterval
		}
		if cfg[0].RetryBackoff > 0 {
			config.RetryBackoff = cfg[0].RetryBackoff
		}
		if cfg[0].MaxPolicyAge > 0 {
			config.MaxPolicyAge = cfg[0].MaxPolicyAge
		}
	}

	holder := NewSnapshotHolder()
	engine := NewLocalEngine(holder, EngineConfig{
		MaxPolicyAge: config.MaxPolicyAge,
	})

	return &Runtime{
		source: source,
		holder: holder,
		engine: engine,
		cfg:    config,
	}, nil
}

// Bootstrap synchronously loads the initial snapshot from the source before the service begins
// serving requests. If loading fails, it fails closed and records the refresh failure.
func (r *Runtime) Bootstrap(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()

	now := time.Now()
	snapshot, err := r.source.LoadSnapshot(ctx)
	if err != nil {
		r.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("bootstrap policy snapshot failed: %w", err)
	}

	if err := r.holder.Set(snapshot); err != nil {
		r.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("install initial policy snapshot failed: %w", err)
	}

	r.holder.RecordRefreshSuccess(now)
	return nil
}

// Start begins the background policy synchronization loop.
// It implements a one-shot lifecycle: once stopped, the runtime cannot be restarted.
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.stopped {
		return ErrRuntimeStopped
	}
	if r.started {
		return ErrRuntimeAlreadyStarted
	}

	workerCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.started = true
	done := make(chan struct{})
	r.done = done

	go r.worker(workerCtx, done)
	return nil
}

// Stop gracefully shuts down the background syncer and waits for completion.
func (r *Runtime) Stop() {
	r.mu.Lock()
	if !r.started || r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	if r.cancel != nil {
		r.cancel()
	}
	done := r.done
	r.mu.Unlock()

	if done != nil {
		<-done
	}
}

// SyncOnce checks the latest policy version from the source and reloads if newer than the local version.
// Concurrent calls are serialized to prevent older snapshots from replacing newer ones.
func (r *Runtime) SyncOnce(ctx context.Context) error {
	r.syncMu.Lock()
	defer r.syncMu.Unlock()

	now := time.Now()
	latestVer, err := r.source.GetLatestVersion(ctx)
	if err != nil {
		r.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("check latest policy version: %w", err)
	}

	currentVer := r.holder.Version()
	if latestVer <= currentVer && r.holder.IsReady() {
		// Local snapshot is already current; record success confirmation
		r.holder.RecordRefreshSuccess(now)
		return nil
	}

	snapshot, err := r.source.LoadSnapshot(ctx)
	if err != nil {
		r.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("load policy snapshot: %w", err)
	}

	if err := r.holder.Set(snapshot); err != nil {
		if errors.Is(err, ErrOlderSnapshotVersion) {
			// A concurrent reload already installed this or newer version
			return nil
		}
		r.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("install policy snapshot: %w", err)
	}

	r.holder.RecordRefreshSuccess(now)
	return nil
}

// Engine returns the shared authorization Engine backed by the local cached snapshot.
func (r *Runtime) Engine() Engine {
	return r.engine
}

// Holder returns the underlying SnapshotHolder.
func (r *Runtime) Holder() *SnapshotHolder {
	return r.holder
}

// Status returns current diagnostics, freshness, and health metrics for the policy snapshot.
func (r *Runtime) Status() SnapshotStatus {
	return r.holder.Status(r.cfg.MaxPolicyAge)
}

// IsReady returns true if a usable, fresh snapshot is loaded.
func (r *Runtime) IsReady() bool {
	return r.engine.IsReady()
}

func (r *Runtime) worker(ctx context.Context, done chan struct{}) {
	defer close(done)

	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.SyncOnce(ctx); err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(r.cfg.RetryBackoff):
					_ = r.SyncOnce(ctx)
				}
			}
		}
	}
}
