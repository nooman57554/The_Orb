package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

// PolicyDistributionService manages authorization snapshot loading, local caching, and distribution.
type PolicyDistributionService struct {
	loader repository.SnapshotLoader
	holder *authorization.SnapshotHolder
	engine *authorization.LocalEngine

	mu          sync.RWMutex
	subscribers []chan *authorization.PolicySnapshot
}

// NewPolicyDistributionService creates a new PolicyDistributionService.
func NewPolicyDistributionService(
	loader repository.SnapshotLoader,
	maxPolicyAge ...time.Duration,
) (*PolicyDistributionService, error) {
	if loader == nil {
		return nil, fmt.Errorf("snapshot loader is required")
	}

	holder := authorization.NewSnapshotHolder()
	var maxAge time.Duration
	if len(maxPolicyAge) > 0 {
		maxAge = maxPolicyAge[0]
	}

	engine := authorization.NewLocalEngine(holder, authorization.EngineConfig{
		MaxPolicyAge: maxAge,
	})

	return &PolicyDistributionService{
		loader:      loader,
		holder:      holder,
		engine:      engine,
		subscribers: make([]chan *authorization.PolicySnapshot, 0),
	}, nil
}

// Bootstrap loads the initial snapshot from the persistence store.
// If loading fails, it fails closed so that unready policy cannot permit requests.
func (s *PolicyDistributionService) Bootstrap(ctx context.Context) error {
	snapshot, err := s.loader.LoadSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("bootstrap snapshot: %w", err)
	}

	if err := s.holder.Set(snapshot); err != nil {
		return fmt.Errorf("install initial snapshot: %w", err)
	}

	s.broadcast(snapshot)
	return nil
}

// Reload forces a fresh snapshot load from the database and updates the local holder atomically.
func (s *PolicyDistributionService) Reload(ctx context.Context) error {
	snapshot, err := s.loader.LoadSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("reload snapshot: %w", err)
	}

	if err := s.holder.Set(snapshot); err != nil {
		// If the new snapshot has an equal version, that is acceptable if no new events occurred
		return nil
	}

	s.broadcast(snapshot)
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
