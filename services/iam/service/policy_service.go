package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

// PolicyDistributionService manages authorization snapshot loading, local caching, periodic background
// synchronization, and subscriber broadcasting.
type PolicyDistributionService struct {
	loader       repository.SnapshotLoader
	holder       *authorization.SnapshotHolder
	engine       *authorization.LocalEngine
	syncer       *authorization.PolicySyncer
	maxPolicyAge time.Duration

	mu          sync.RWMutex
	subscribers []chan *authorization.PolicySnapshot
}

// NewPolicyDistributionService creates a new PolicyDistributionService.
// Optional durations: opts[0] is maxPolicyAge (0 disables expiration), opts[1] is pollInterval (default 5s).
func NewPolicyDistributionService(
	loader repository.SnapshotLoader,
	opts ...time.Duration,
) (*PolicyDistributionService, error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader is required")
	}

	var maxPolicyAge time.Duration
	if len(opts) > 0 {
		maxPolicyAge = opts[0]
	}

	holder := authorization.NewSnapshotHolder()
	engine := authorization.NewLocalEngine(holder, authorization.EngineConfig{
		MaxPolicyAge: maxPolicyAge,
	})

	syncerCfg := authorization.DefaultSyncerConfig()
	if len(opts) > 1 && opts[1] > 0 {
		syncerCfg.PollInterval = opts[1]
	}

	syncer, err := authorization.NewPolicySyncer(loader, holder, syncerCfg)
	if err != nil {
		return nil, fmt.Errorf("create policy syncer: %w", err)
	}

	return &PolicyDistributionService{
		loader:       loader,
		holder:       holder,
		engine:       engine,
		syncer:       syncer,
		maxPolicyAge: maxPolicyAge,
		subscribers:  make([]chan *authorization.PolicySnapshot, 0),
	}, nil
}

// Bootstrap loads the initial snapshot from the persistence store before traffic is served.
// If loading fails, it fails closed so that unready policy cannot permit requests.
func (s *PolicyDistributionService) Bootstrap(ctx context.Context) error {
	if err := s.syncer.Bootstrap(ctx); err != nil {
		return fmt.Errorf("bootstrap snapshot: %w", err)
	}

	if snap, err := s.holder.Get(); err == nil {
		s.broadcast(snap)
	}
	return nil
}

// Start begins the background policy synchronization loop.
func (s *PolicyDistributionService) Start(ctx context.Context) error {
	return s.syncer.Start(ctx)
}

// Stop gracefully shuts down the background syncer and waits for completion.
func (s *PolicyDistributionService) Stop() {
	s.syncer.Stop()
}

// Reload forces an immediate check and reload of the latest snapshot from the database.
func (s *PolicyDistributionService) Reload(ctx context.Context) error {
	oldVer := s.holder.Version()
	if err := s.syncer.SyncOnce(ctx); err != nil {
		return fmt.Errorf("reload snapshot: %w", err)
	}

	if s.holder.Version() > oldVer {
		if snap, err := s.holder.Get(); err == nil {
			s.broadcast(snap)
		}
	}
	return nil
}

// Engine returns the local authorization engine backed by the cached snapshot.
func (s *PolicyDistributionService) Engine() authorization.Engine {
	return s.engine
}

// Holder returns the underlying SnapshotHolder.
func (s *PolicyDistributionService) Holder() *authorization.SnapshotHolder {
	return s.holder
}

// Status returns current diagnostics, freshness, and health metrics for the policy snapshot.
func (s *PolicyDistributionService) Status() authorization.SnapshotStatus {
	return s.holder.Status(s.maxPolicyAge)
}

// GetSnapshot returns the current active snapshot.
func (s *PolicyDistributionService) GetSnapshot() (*authorization.PolicySnapshot, error) {
	return s.holder.Get()
}

// IsReady returns true if a usable, fresh snapshot is loaded.
func (s *PolicyDistributionService) IsReady() bool {
	return s.engine.IsReady()
}

// Subscribe returns a channel that receives newly published PolicySnapshots.
func (s *PolicyDistributionService) Subscribe() <-chan *authorization.PolicySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := make(chan *authorization.PolicySnapshot, 10)
	s.subscribers = append(s.subscribers, ch)

	// Send current snapshot if available
	if snap, err := s.holder.Get(); err == nil {
		ch <- snap
	}

	return ch
}

func (s *PolicyDistributionService) broadcast(snapshot *authorization.PolicySnapshot) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, ch := range s.subscribers {
		select {
		case ch <- snapshot:
		default:
			// Non-blocking drop if consumer buffer is full
		}
	}
}
