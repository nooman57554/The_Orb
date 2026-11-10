package authorization

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SnapshotSource defines the methods required by PolicySyncer to poll and load policy snapshots.
type SnapshotSource interface {
	GetLatestVersion(ctx context.Context) (int64, error)
	LoadSnapshot(ctx context.Context) (*PolicySnapshot, error)
}

// SyncerConfig configures the background PolicySyncer.
type SyncerConfig struct {
	PollInterval time.Duration
	RetryBackoff time.Duration
}

// DefaultSyncerConfig provides recommended defaults for policy synchronization.
func DefaultSyncerConfig() SyncerConfig {
	return SyncerConfig{
		PollInterval: 5 * time.Second,
		RetryBackoff: 1 * time.Second,
	}
}

// PolicySyncer maintains an up-to-date, monotonically increasing PolicySnapshot
// in a local SnapshotHolder by periodically checking the remote SnapshotSource.
type PolicySyncer struct {
	source SnapshotSource
	holder *SnapshotHolder
	cfg    SyncerConfig

	mu        sync.Mutex
	running   bool
	cancel    context.CancelFunc
	done      chan struct{}
	syncMutex sync.Mutex // guarantees no concurrent overlapping reloads
}

// NewPolicySyncer creates a new PolicySyncer for the provided source and snapshot holder.
func NewPolicySyncer(source SnapshotSource, holder *SnapshotHolder, cfg ...SyncerConfig) (*PolicySyncer, error) {
	if source == nil {
		return nil, fmt.Errorf("snapshot source is required")
	}
	if holder == nil {
		return nil, fmt.Errorf("snapshot holder is required")
	}

	config := DefaultSyncerConfig()
	if len(cfg) > 0 {
		if cfg[0].PollInterval > 0 {
			config.PollInterval = cfg[0].PollInterval
		}
		if cfg[0].RetryBackoff > 0 {
			config.RetryBackoff = cfg[0].RetryBackoff
		}
	}

	return &PolicySyncer{
		source: source,
		holder: holder,
		cfg:    config,
	}, nil
}

// Bootstrap synchronously loads the initial snapshot from the source before the service begins
// serving requests. If loading fails, it fails closed and records the refresh failure.
func (s *PolicySyncer) Bootstrap(ctx context.Context) error {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()

	now := time.Now()
	snapshot, err := s.source.LoadSnapshot(ctx)
	if err != nil {
		s.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("bootstrap policy snapshot failed: %w", err)
	}

	if err := s.holder.Set(snapshot); err != nil {
		s.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("install initial policy snapshot failed: %w", err)
	}

	s.holder.RecordRefreshSuccess(now)
	return nil
}

// SyncOnce checks the latest policy version from the source and reloads if newer than the local version.
// Concurrent calls are serialized to prevent older snapshots from replacing newer ones.
func (s *PolicySyncer) SyncOnce(ctx context.Context) error {
	s.syncMutex.Lock()
	defer s.syncMutex.Unlock()

	now := time.Now()
	latestVer, err := s.source.GetLatestVersion(ctx)
	if err != nil {
		s.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("check latest policy version: %w", err)
	}

	currentVer := s.holder.Version()
	if latestVer <= currentVer && s.holder.IsReady() {
		// Local snapshot is already current; record success heartbeat
		s.holder.RecordRefreshSuccess(now)
		return nil
	}

	snapshot, err := s.source.LoadSnapshot(ctx)
	if err != nil {
		s.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("load policy snapshot: %w", err)
	}

	if err := s.holder.Set(snapshot); err != nil {
		if errors.Is(err, ErrOlderSnapshotVersion) {
			// A concurrent reload already installed this or newer version
			return nil
		}
		s.holder.RecordRefreshFailure(err, now)
		return fmt.Errorf("install policy snapshot: %w", err)
	}

	s.holder.RecordRefreshSuccess(now)
	return nil
}

// Start spawns the background polling loop. It returns immediately.
func (s *PolicySyncer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	pollCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.running = true
	s.done = make(chan struct{})

	go s.pollLoop(pollCtx)
	return nil
}

// Stop gracefully terminates the background polling loop and waits for it to exit.
func (s *PolicySyncer) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	done := s.done
	s.mu.Unlock()

	if done != nil {
		<-done
	}
}

func (s *PolicySyncer) pollLoop(ctx context.Context) {
	defer close(s.done)

	ticker := time.NewTicker(s.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.SyncOnce(ctx); err != nil {
				// Retry with configured backoff if context still alive
				select {
				case <-ctx.Done():
					return
				case <-time.After(s.cfg.RetryBackoff):
					_ = s.SyncOnce(ctx)
				}
			}
		}
	}
}
