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

func (m *mockSnapshotSource) setFailVersion(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failVersion = fail
}

func TestRuntime_BootstrapAndValidation(t *testing.T) {
	ctx := context.Background()

	// 1. Nil source fails
	if _, err := NewRuntime(nil); !errors.Is(err, ErrNilSnapshotSource) {
		t.Fatalf("expected ErrNilSnapshotSource, got %v", err)
	}

	// 2. Successful bootstrap
	source := &mockSnapshotSource{version: 1}
	rt, err := NewRuntime(source)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	if err := rt.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap runtime: %v", err)
	}

	if !rt.IsReady() {
		t.Fatalf("expected runtime ready after bootstrap")
	}
	if rt.Holder().Version() != 1 {
		t.Fatalf("expected version 1, got %d", rt.Holder().Version())
	}

	// 3. Failed bootstrap fails closed
	failingSource := &mockSnapshotSource{failSnapshot: true}
	failingRt, err := NewRuntime(failingSource)
	if err != nil {
		t.Fatalf("create failing runtime: %v", err)
	}

	if err := failingRt.Bootstrap(ctx); err == nil {
		t.Fatalf("expected bootstrap error on failing source")
	}
	if failingRt.IsReady() {
		t.Fatalf("expected failing runtime NOT ready")
	}
	if failingRt.Holder().LastRefreshError() == nil {
		t.Fatalf("expected refresh error recorded")
	}
}

func TestRuntime_MultiInstanceDistribution(t *testing.T) {
	ctx := context.Background()

	// Shared source representing the central database
	source := &mockSnapshotSource{version: 1}

	// Instance 1
	rt1, err := NewRuntime(source, RuntimeConfig{
		PollInterval: 50 * time.Millisecond,
		RetryBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create rt1: %v", err)
	}

	// Instance 2
	rt2, err := NewRuntime(source, RuntimeConfig{
		PollInterval: 50 * time.Millisecond,
		RetryBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create rt2: %v", err)
	}

	// Initial bootstrap
	if err := rt1.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap rt1: %v", err)
	}
	if err := rt2.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap rt2: %v", err)
	}

	// Start both
	if err := rt1.Start(ctx); err != nil {
		t.Fatalf("start rt1: %v", err)
	}
	defer rt1.Stop()

	if err := rt2.Start(ctx); err != nil {
		t.Fatalf("start rt2: %v", err)
	}
	defer rt2.Stop()

	// Update central version to 2
	source.setVersion(2)

	// Both instances must independently observe version 2
	checkCondition := func(rt *Runtime, targetVer int64, timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if rt.Holder().Version() >= targetVer {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}

	if !checkCondition(rt1, 2, 2*time.Second) {
		t.Fatalf("instance 1 failed to update to version 2 within timeout; version is %d", rt1.Holder().Version())
	}
	if !checkCondition(rt2, 2, 2*time.Second) {
		t.Fatalf("instance 2 failed to update to version 2 within timeout; version is %d", rt2.Holder().Version())
	}
}

func TestRuntime_StalenessPolicyWithConfirmation(t *testing.T) {
	ctx := context.Background()

	// Snapshot was created 10 minutes ago, but confirmation succeeds
	createdAt := time.Now().Add(-10 * time.Minute)
	source := &mockSnapshotSource{
		version: 1,
		snapshotFunc: func(v int64) *PolicySnapshot {
			return makeTestSnapshot(v, createdAt)
		},
	}

	rt, err := NewRuntime(source, RuntimeConfig{
		PollInterval: 50 * time.Millisecond,
		RetryBackoff: 10 * time.Millisecond,
		MaxPolicyAge: 1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	if err := rt.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// Because Bootstrap recorded refresh success just now, the engine must NOT be stale,
	// even though the snapshot CreatedAt is 10 minutes old!
	if !rt.IsReady() {
		t.Fatalf("expected runtime to be ready because policy version was successfully confirmed")
	}

	adminPrincipal := &identity.Principal{
		UserID:    uuid.MustParse("01a00000-0000-7000-8000-000000000010"),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	d, err := rt.Engine().Authorize(ctx, AuthorizationRequest{
		Principal:  adminPrincipal,
		Permission: PermPlatformTenantList,
	})
	if err != nil || !d.Allowed {
		t.Fatalf("expected allowed, got decision: %+v, err: %v", d, err)
	}

	// Now simulate that the database is down for longer than MaxPolicyAge
	// Set last successful refresh to 2 minutes ago
	rt.Holder().RecordRefreshFailure(errors.New("db down"), time.Now())
	// Artificially age the last successful refresh
	rt.Holder().mu.Lock()
	rt.Holder().lastSuccessfulRefresh = time.Now().Add(-2 * time.Minute)
	rt.Holder().mu.Unlock()

	// Now the runtime must fail closed with ErrPolicyStale
	d, err = rt.Engine().Authorize(ctx, AuthorizationRequest{
		Principal:  adminPrincipal,
		Permission: PermPlatformTenantList,
	})
	if !errors.Is(err, ErrPolicyStale) || d.Allowed || d.Reason != ReasonPolicyStale {
		t.Fatalf("expected fail-closed with ErrPolicyStale, got decision: %+v, err: %v", d, err)
	}
}

func TestRuntime_LifecycleAndRaceRegression(t *testing.T) {
	ctx := context.Background()
	source := &mockSnapshotSource{version: 1}

	rt, err := NewRuntime(source, RuntimeConfig{
		PollInterval: 20 * time.Millisecond,
		RetryBackoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	if err := rt.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	// Start
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Starting again must return ErrRuntimeAlreadyStarted
	if err := rt.Start(ctx); !errors.Is(err, ErrRuntimeAlreadyStarted) {
		t.Fatalf("expected ErrRuntimeAlreadyStarted, got %v", err)
	}

	// Let it run for several polling cycles
	time.Sleep(60 * time.Millisecond)

	// Stop cleanly
	rt.Stop()

	// Stopping again is idempotent
	rt.Stop()

	// Starting after stop must return ErrRuntimeStopped (one-shot lifecycle)
	if err := rt.Start(ctx); !errors.Is(err, ErrRuntimeStopped) {
		t.Fatalf("expected ErrRuntimeStopped, got %v", err)
	}
}

func TestRuntime_TransientFailureAndRetry(t *testing.T) {
	ctx := context.Background()
	source := &mockSnapshotSource{version: 1}

	rt, err := NewRuntime(source, RuntimeConfig{
		PollInterval: 30 * time.Millisecond,
		RetryBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}

	if err := rt.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer rt.Stop()

	// Simulate transient version query failure
	source.setFailVersion(true)
	time.Sleep(50 * time.Millisecond)

	// Verify error was recorded on holder
	if rt.Holder().LastRefreshError() == nil {
		t.Fatalf("expected last refresh error recorded during transient failure")
	}

	// Recover DB and bump version
	source.setFailVersion(false)
	source.setVersion(2)

	// Wait for retry recovery
	deadline := time.Now().Add(2 * time.Second)
	updated := false
	for time.Now().Before(deadline) {
		if rt.Holder().Version() == 2 && rt.Holder().LastRefreshError() == nil {
			updated = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	if !updated {
		t.Fatalf("runtime failed to recover from transient error and reach version 2")
	}
}

func TestRuntime_ConcurrentSyncSerialization(t *testing.T) {
	ctx := context.Background()
	source := &mockSnapshotSource{version: 1}

	rt, err := NewRuntime(source)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	if err := rt.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}

	var activeCalls int64
	var maxConcurrent int64

	source.snapshotFunc = func(v int64) *PolicySnapshot {
		cur := atomic.AddInt64(&activeCalls, 1)
		for {
			oldMax := atomic.LoadInt64(&maxConcurrent)
			if cur <= oldMax || atomic.CompareAndSwapInt64(&maxConcurrent, oldMax, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt64(&activeCalls, -1)
		return makeTestSnapshot(v, time.Now())
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(v int64) {
			defer wg.Done()
			source.setVersion(v)
			_ = rt.SyncOnce(ctx)
		}(int64(i + 2))
	}
	wg.Wait()

	if atomic.LoadInt64(&maxConcurrent) > 1 {
		t.Errorf("expected max concurrent snapshot loads to be 1, got %d", maxConcurrent)
	}
}
