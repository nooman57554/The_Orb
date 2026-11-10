package authorization

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

// mockSnapshotSource implements SnapshotSource with controllable version and failure simulation.
type mockSnapshotSource struct {
	mu           sync.Mutex
	version      int64
	snapshotFunc func(v int64) *PolicySnapshot
	failVersion  bool
	failSnapshot bool
}

func (m *mockSnapshotSource) GetLatestVersion(ctx context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failVersion {
		return 0, errors.New("database connection timeout")
	}
	return m.version, nil
}

func (m *mockSnapshotSource) LoadSnapshot(ctx context.Context) (*PolicySnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.failSnapshot {
		return nil, errors.New("database query error")
	}
	if m.snapshotFunc != nil {
		return m.snapshotFunc(m.version), nil
	}
	return makeTestSnapshot(m.version, time.Now()), nil
}

func (m *mockSnapshotSource) setVersion(v int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.version = v
}

func TestPolicySyncer_MultiInstanceDistribution(t *testing.T) {
	ctx := context.Background()

	// Shared source representing the central IAM database
	source := &mockSnapshotSource{
		version: 1,
	}

	// Instance 1
	holder1 := NewSnapshotHolder()
	syncer1, err := NewPolicySyncer(source, holder1, SyncerConfig{
		PollInterval: 50 * time.Millisecond,
		RetryBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create syncer 1: %v", err)
	}

	// Instance 2
	holder2 := NewSnapshotHolder()
	syncer2, err := NewPolicySyncer(source, holder2, SyncerConfig{
		PollInterval: 50 * time.Millisecond,
		RetryBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create syncer 2: %v", err)
	}

	// 1. Initial bootstrap of both instances
	if err := syncer1.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap instance 1: %v", err)
	}
	if err := syncer2.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap instance 2: %v", err)
	}

	if holder1.Version() != 1 || holder2.Version() != 1 {
		t.Fatalf("expected both instances at version 1, got %d and %d", holder1.Version(), holder2.Version())
	}

	// 2. Start background sync loops
	if err := syncer1.Start(ctx); err != nil {
		t.Fatalf("start syncer 1: %v", err)
	}
	defer syncer1.Stop()

	if err := syncer2.Start(ctx); err != nil {
		t.Fatalf("start syncer 2: %v", err)
	}
	defer syncer2.Stop()

	// 3. Central policy update to version 2
	source.setVersion(2)

	// Wait for both instances to detect and atomically install version 2
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if holder1.Version() == 2 && holder2.Version() == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if holder1.Version() != 2 {
		t.Errorf("instance 1 failed to reach version 2, at %d", holder1.Version())
	}
	if holder2.Version() != 2 {
		t.Errorf("instance 2 failed to reach version 2, at %d", holder2.Version())
	}

	// Verify instances hold independent in-memory copies
	snap1, _ := holder1.Get()
	snap2, _ := holder2.Get()
	if snap1 == snap2 {
		t.Errorf("instances must hold distinct snapshot copies, got shared pointer")
	}

	// 4. Central policy update to version 3
	source.setVersion(3)

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if holder1.Version() == 3 && holder2.Version() == 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if holder1.Version() != 3 || holder2.Version() != 3 {
		t.Errorf("expected both instances at version 3, got %d and %d", holder1.Version(), holder2.Version())
	}
}

func TestPolicySyncer_IndependentFailureAndRetry(t *testing.T) {
	ctx := context.Background()

	source := &mockSnapshotSource{
		version: 1,
	}

	holder1 := NewSnapshotHolder()
	syncer1, _ := NewPolicySyncer(source, holder1, SyncerConfig{
		PollInterval: 30 * time.Millisecond,
		RetryBackoff: 10 * time.Millisecond,
	})

	holder2 := NewSnapshotHolder()
	syncer2, _ := NewPolicySyncer(source, holder2, SyncerConfig{
		PollInterval: 30 * time.Millisecond,
		RetryBackoff: 10 * time.Millisecond,
	})

	_ = syncer1.Bootstrap(ctx)
	_ = syncer2.Bootstrap(ctx)

	// Simulate source failure for version check
	source.mu.Lock()
	source.failVersion = true
	source.mu.Unlock()

	// SyncOnce fails gracefully and records error on holder1
	err := syncer1.SyncOnce(ctx)
	if err == nil {
		t.Errorf("expected error on failed version check, got nil")
	}
	if holder1.LastRefreshError() == nil {
		t.Errorf("expected LastRefreshError to be recorded on holder")
	}
	// Previous valid snapshot must be preserved!
	if holder1.Version() != 1 {
		t.Errorf("previous valid snapshot must be preserved on error, got version %d", holder1.Version())
	}

	// Instance 2 is also tested: failure on one doesn't crash the other
	err = syncer2.SyncOnce(ctx)
	if err == nil {
		t.Errorf("expected error on instance 2, got nil")
	}
	if holder2.Version() != 1 {
		t.Errorf("instance 2 must preserve version 1, got %d", holder2.Version())
	}

	// Heal source and bump version
	source.mu.Lock()
	source.failVersion = false
	source.version = 5
	source.mu.Unlock()

	// Retry succeeds
	if err := syncer1.SyncOnce(ctx); err != nil {
		t.Fatalf("expected successful retry after healing source, got %v", err)
	}
	if holder1.Version() != 5 {
		t.Errorf("expected instance 1 at version 5, got %d", holder1.Version())
	}
	if holder1.LastRefreshError() != nil {
		t.Errorf("expected LastRefreshError cleared after success, got %v", holder1.LastRefreshError())
	}
}

func TestPolicySyncer_StalenessPolicyEnforcement(t *testing.T) {
	ctx := context.Background()

	// Create snapshot timestamped 30 minutes in the past
	pastTime := time.Now().Add(-30 * time.Minute)
	source := &mockSnapshotSource{
		version: 1,
		snapshotFunc: func(v int64) *PolicySnapshot {
			return makeTestSnapshot(v, pastTime)
		},
	}

	holder := NewSnapshotHolder()
	syncer, _ := NewPolicySyncer(source, holder)
	_ = syncer.Bootstrap(ctx)

	// Configure engine with 15 minute MaxPolicyAge
	engine := NewLocalEngine(holder, EngineConfig{
		MaxPolicyAge: 15 * time.Minute,
	})

	if engine.IsReady() {
		t.Errorf("expected engine to report NOT ready when snapshot is stale")
	}

	adminUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000010")
	principal := &identity.Principal{
		UserID:    adminUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// Authorize must fail closed with ErrPolicyStale
	decision, err := engine.Authorize(ctx, AuthorizationRequest{
		Principal:  principal,
		Permission: PermPlatformTenantList,
	})
	if !errors.Is(err, ErrPolicyStale) {
		t.Errorf("expected ErrPolicyStale, got %v", err)
	}
	if decision.Allowed {
		t.Errorf("stale policy must NOT allow authorization")
	}
	if decision.Reason != ReasonPolicyStale {
		t.Errorf("expected ReasonPolicyStale, got %q", decision.Reason)
	}
}

func TestPolicySyncer_GracefulShutdown(t *testing.T) {
	ctx := context.Background()
	source := &mockSnapshotSource{version: 1}
	holder := NewSnapshotHolder()
	syncer, _ := NewPolicySyncer(source, holder, SyncerConfig{
		PollInterval: 10 * time.Millisecond,
	})

	_ = syncer.Bootstrap(ctx)
	_ = syncer.Start(ctx)

	// Calling Stop must return cleanly and cancel background worker
	stopped := make(chan struct{})
	go func() {
		syncer.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatalf("syncer.Stop did not terminate within timeout")
	}
}

func TestPolicySyncer_PreventsOverlappingReloads(t *testing.T) {
	ctx := context.Background()

	var activeCalls int64
	var maxConcurrent int64

	source := &mockSnapshotSource{
		version: 1,
		snapshotFunc: func(v int64) *PolicySnapshot {
			cur := atomic.AddInt64(&activeCalls, 1)
			defer atomic.AddInt64(&activeCalls, -1)

			for {
				max := atomic.LoadInt64(&maxConcurrent)
				if cur <= max || atomic.CompareAndSwapInt64(&maxConcurrent, max, cur) {
					break
				}
			}

			time.Sleep(20 * time.Millisecond)
			return makeTestSnapshot(v, time.Now())
		},
	}

	holder := NewSnapshotHolder()
	syncer, _ := NewPolicySyncer(source, holder)
	_ = syncer.Bootstrap(ctx)

	// Trigger 10 concurrent SyncOnce calls
	var wg sync.WaitGroup
	source.setVersion(2)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = syncer.SyncOnce(ctx)
		}()
	}

	wg.Wait()

	if max := atomic.LoadInt64(&maxConcurrent); max > 1 {
		t.Errorf("expected maximum concurrent reloads to be 1, got %d", max)
	}
}
