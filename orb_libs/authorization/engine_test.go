package authorization

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

func makeTestSnapshot(version int64, createdAt time.Time) *PolicySnapshot {
	tenantA := "01a00000-0000-7000-8000-000000000001"

	userPlatformAdmin := "01a00000-0000-7000-8000-000000000010"
	userTenantAdminA := "01a00000-0000-7000-8000-000000000020"
	userTenantMemberA := "01a00000-0000-7000-8000-000000000030"
	userInactive := "01a00000-0000-7000-8000-000000000040"

	rolePlatformAdminID := "01a00000-0000-7000-8000-000000000100"
	roleTenantAdminRWID := "01a00000-0000-7000-8000-000000000200"
	roleTenantUserID := "01a00000-0000-7000-8000-000000000300"
	roleCustomTenantAID := "01a00000-0000-7000-8000-000000000400"

	return &PolicySnapshot{
		Version:   version,
		CreatedAt: createdAt,
		Users: map[string]UserPolicy{
			userPlatformAdmin: {Active: true},
			userTenantAdminA:  {Active: true},
			userTenantMemberA: {Active: true},
			userInactive:      {Active: false},
		},
		PlatformAssignments: map[string]string{
			userPlatformAdmin: rolePlatformAdminID,
		},
		TenantAssignments: map[string]map[string]string{
			userTenantAdminA: {
				tenantA: roleTenantAdminRWID,
			},
			userTenantMemberA: {
				tenantA: roleTenantUserID,
			},
		},
		Roles: map[string]RolePolicy{
			rolePlatformAdminID: {
				ID:    rolePlatformAdminID,
				Name:  "PLATFORM_ADMIN",
				Scope: RoleScopePlatform,
				Permissions: []string{
					PermPlatformTenantList,
					PermPlatformTenantRead,
					PermPlatformTenantCreate,
					PermPlatformRoleAssign,
					PermPlatformUserRead,
				},
			},
			roleTenantAdminRWID: {
				ID:    roleTenantAdminRWID,
				Name:  "TENANT_ADMIN_RW",
				Scope: RoleScopeSystemTenant,
				Permissions: []string{
					PermTenantRead,
					PermTenantUserRead,
					PermTenantUserCreate,
					PermTenantUserAssignRole,
					PermTenantUserRemove,
					PermTenantRoleRead,
					PermTenantRoleCreate,
				},
			},
			roleTenantUserID: {
				ID:    roleTenantUserID,
				Name:  "TENANT_USER",
				Scope: RoleScopeSystemTenant,
				Permissions: []string{
					PermTenantRead,
					PermTenantUserRead,
				},
			},
			roleCustomTenantAID: {
				ID:       roleCustomTenantAID,
				Name:     "CUSTOM_A",
				Scope:    RoleScopeCustomTenant,
				TenantID: &tenantA,
				Permissions: []string{
					PermTenantRead,
				},
			},
		},
		Permissions: map[string]PermissionDefinition{
			PermPlatformTenantList:   {Name: PermPlatformTenantList, Scope: ScopePlatform},
			PermPlatformTenantRead:   {Name: PermPlatformTenantRead, Scope: ScopePlatform},
			PermPlatformTenantCreate: {Name: PermPlatformTenantCreate, Scope: ScopePlatform},
			PermPlatformRoleAssign:   {Name: PermPlatformRoleAssign, Scope: ScopePlatform},
			PermPlatformUserRead:     {Name: PermPlatformUserRead, Scope: ScopePlatform},

			PermTenantRead:           {Name: PermTenantRead, Scope: ScopeTenant},
			PermTenantUserRead:       {Name: PermTenantUserRead, Scope: ScopeTenant},
			PermTenantUserCreate:     {Name: PermTenantUserCreate, Scope: ScopeTenant},
			PermTenantUserAssignRole: {Name: PermTenantUserAssignRole, Scope: ScopeTenant},
			PermTenantUserRemove:     {Name: PermTenantUserRemove, Scope: ScopeTenant},
			PermTenantRoleRead:       {Name: PermTenantRoleRead, Scope: ScopeTenant},
			PermTenantRoleCreate:     {Name: PermTenantRoleCreate, Scope: ScopeTenant},
		},
	}
}

func TestLocalEngine_PlatformPermissions(t *testing.T) {
	ctx := context.Background()
	holder := NewSnapshotHolder()
	snapshot := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapshot); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}

	engine := NewLocalEngine(holder)

	adminUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000010")
	tenantUserUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000020")

	adminPrincipal := &identity.Principal{
		UserID:    adminUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	tenantUserPrincipal := &identity.Principal{
		UserID:    tenantUserUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// 1. Platform permission allowed for platform admin
	d, err := engine.Authorize(ctx, AuthorizationRequest{
		Principal:  adminPrincipal,
		Permission: PermPlatformTenantList,
	})
	if err != nil || !d.Allowed || d.Reason != ReasonAllowed {
		t.Errorf("expected allowed for platform admin on platform.tenant.list, got: %+v, err: %v", d, err)
	}

	// 2. Platform permission denied for user without platform role
	d, err = engine.Authorize(ctx, AuthorizationRequest{
		Principal:  tenantUserPrincipal,
		Permission: PermPlatformTenantList,
	})
	if err != nil || d.Allowed || d.Reason != ReasonNoPlatformRole {
		t.Errorf("expected denied (no platform role) for tenant user on platform permission, got: %+v, err: %v", d, err)
	}
}

func TestLocalEngine_TenantPermissions(t *testing.T) {
	ctx := context.Background()
	holder := NewSnapshotHolder()
	snapshot := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapshot); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}

	engine := NewLocalEngine(holder)

	tenantAdminUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000020")
	tenantA := "01a00000-0000-7000-8000-000000000001"
	tenantB := "01a00000-0000-7000-8000-000000000002"

	tenantAdminPrincipal := &identity.Principal{
		UserID:    tenantAdminUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// 1. Tenant permission allowed in Tenant A
	d, err := engine.Authorize(ctx, AuthorizationRequest{
		Principal:  tenantAdminPrincipal,
		Permission: PermTenantUserCreate,
		TenantID:   tenantA,
	})
	if err != nil || !d.Allowed || d.Reason != ReasonAllowed {
		t.Errorf("expected allowed in Tenant A, got: %+v, err: %v", d, err)
	}

	// 2. Cross-tenant isolation: Tenant A admin cannot access Tenant B
	d, err = engine.Authorize(ctx, AuthorizationRequest{
		Principal:  tenantAdminPrincipal,
		Permission: PermTenantUserCreate,
		TenantID:   tenantB,
	})
	if err != nil || d.Allowed || d.Reason != ReasonNoTenantRole {
		t.Errorf("expected denied (no tenant role in B), got: %+v, err: %v", d, err)
	}

	// 3. Missing tenant scope for tenant-scoped permission
	d, err = engine.Authorize(ctx, AuthorizationRequest{
		Principal:  tenantAdminPrincipal,
		Permission: PermTenantUserCreate,
		TenantID:   "",
	})
	if err != nil || d.Allowed || d.Reason != ReasonMissingTenantScope {
		t.Errorf("expected missing tenant scope denial, got: %+v, err: %v", d, err)
	}
}

func TestLocalEngine_PlatformRoleDoesNotImplyTenantMembership(t *testing.T) {
	ctx := context.Background()
	holder := NewSnapshotHolder()
	snapshot := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapshot); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}

	engine := NewLocalEngine(holder)

	adminUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000010")
	tenantA := "01a00000-0000-7000-8000-000000000001"

	adminPrincipal := &identity.Principal{
		UserID:    adminUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// Platform admin does NOT automatically hold tenant permissions in Tenant A
	d, err := engine.Authorize(ctx, AuthorizationRequest{
		Principal:  adminPrincipal,
		Permission: PermTenantUserCreate,
		TenantID:   tenantA,
	})
	if err != nil || d.Allowed || d.Reason != ReasonNoTenantRole {
		t.Errorf("platform role must not imply tenant membership, got: %+v, err: %v", d, err)
	}
}

func TestLocalEngine_TenantRoleDoesNotGrantPlatformAccess(t *testing.T) {
	ctx := context.Background()
	holder := NewSnapshotHolder()
	snapshot := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapshot); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}

	engine := NewLocalEngine(holder)

	tenantAdminUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000020")
	tenantAdminPrincipal := &identity.Principal{
		UserID:    tenantAdminUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	d, err := engine.Authorize(ctx, AuthorizationRequest{
		Principal:  tenantAdminPrincipal,
		Permission: PermPlatformRoleAssign,
	})
	if err != nil || d.Allowed || d.Reason != ReasonNoPlatformRole {
		t.Errorf("tenant role must not grant platform access, got: %+v, err: %v", d, err)
	}
}

func TestLocalEngine_InactiveUserDenied(t *testing.T) {
	ctx := context.Background()
	holder := NewSnapshotHolder()
	snapshot := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapshot); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}

	engine := NewLocalEngine(holder)

	inactiveUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000040")
	principal := &identity.Principal{
		UserID:    inactiveUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	d, err := engine.Authorize(ctx, AuthorizationRequest{
		Principal:  principal,
		Permission: PermPlatformTenantList,
	})
	if err != nil || d.Allowed || d.Reason != ReasonUserInactive {
		t.Errorf("expected user_inactive denial, got: %+v, err: %v", d, err)
	}
}

func TestLocalEngine_ResourceOwnershipSelfProfile(t *testing.T) {
	ctx := context.Background()
	holder := NewSnapshotHolder()
	snapshot := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapshot); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}

	engine := NewLocalEngine(holder)

	memberUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000030")
	otherUserUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000020")

	memberPrincipal := &identity.Principal{
		UserID:    memberUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// 1. Member reads their own profile: allowed by ownership
	d, err := engine.Authorize(ctx, AuthorizationRequest{
		Principal:    memberPrincipal,
		Permission:   PermPlatformUserRead,
		ResourceType: "user",
		ResourceID:   memberUUID.String(),
	})
	if err != nil || !d.Allowed || d.Reason != ReasonAllowed {
		t.Errorf("expected self-profile read allowed by ownership, got: %+v, err: %v", d, err)
	}

	// 2. Member reads another user's profile: denied (no platform permission)
	d, err = engine.Authorize(ctx, AuthorizationRequest{
		Principal:    memberPrincipal,
		Permission:   PermPlatformUserRead,
		ResourceType: "user",
		ResourceID:   otherUserUUID.String(),
	})
	if err != nil || d.Allowed || d.Reason != ReasonNoPlatformRole {
		t.Errorf("expected other user profile read denied for non-platform admin, got: %+v, err: %v", d, err)
	}
}

func TestLocalEngine_FailClosedPolicyUnavailableAndStale(t *testing.T) {
	ctx := context.Background()
	holder := NewSnapshotHolder() // empty

	engine := NewLocalEngine(holder, EngineConfig{
		MaxPolicyAge: 10 * time.Minute,
	})

	principal := &identity.Principal{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// 1. Unavailable snapshot fails closed
	d, err := engine.Authorize(ctx, AuthorizationRequest{
		Principal:  principal,
		Permission: PermPlatformTenantList,
	})
	if err == nil || d.Allowed || d.Reason != ReasonPolicyUnavailable {
		t.Errorf("expected fail-closed on unavailable policy, got: %+v, err: %v", d, err)
	}

	// 2. Stale snapshot fails closed
	staleSnapshot := makeTestSnapshot(1, time.Now().Add(-1*time.Hour))
	if err := holder.Set(staleSnapshot); err != nil {
		t.Fatalf("set stale snapshot: %v", err)
	}

	d, err = engine.Authorize(ctx, AuthorizationRequest{
		Principal:  principal,
		Permission: PermPlatformTenantList,
	})
	if err == nil || d.Allowed || d.Reason != ReasonPolicyStale {
		t.Errorf("expected fail-closed on stale policy, got: %+v, err: %v", d, err)
	}
}

func TestSnapshotHolder_MonotonicityAndValidation(t *testing.T) {
	holder := NewSnapshotHolder()
	snapV1 := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapV1); err != nil {
		t.Fatalf("set v1: %v", err)
	}

	// Setting older or equal version must fail
	snapV1Duplicate := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapV1Duplicate); err == nil {
		t.Errorf("expected error when setting equal version 1")
	}

	snapV0 := makeTestSnapshot(0, time.Now())
	if err := holder.Set(snapV0); err == nil {
		t.Errorf("expected error when setting version 0")
	}

	// Setting v2 succeeds
	snapV2 := makeTestSnapshot(2, time.Now())
	if err := holder.Set(snapV2); err != nil {
		t.Errorf("expected setting v2 to succeed, got: %v", err)
	}
	if holder.Version() != 2 {
		t.Errorf("expected holder version 2, got %d", holder.Version())
	}
}

func TestSnapshotHolder_Concurrency(t *testing.T) {
	holder := NewSnapshotHolder()
	snapV1 := makeTestSnapshot(1, time.Now())
	_ = holder.Set(snapV1)

	engine := NewLocalEngine(holder)

	adminUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000010")
	principal := &identity.Principal{
		UserID:    adminUUID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	var wg sync.WaitGroup
	ctx := context.Background()

	// Concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = engine.Authorize(ctx, AuthorizationRequest{
					Principal:  principal,
					Permission: PermPlatformTenantList,
				})
			}
		}()
	}

	// Concurrent atomic writers
	for i := 2; i <= 20; i++ {
		v := int64(i)
		wg.Add(1)
		go func(ver int64) {
			defer wg.Done()
			snap := makeTestSnapshot(ver, time.Now())
			_ = holder.Set(snap)
		}(v)
	}

	wg.Wait()

	if !holder.IsReady() {
		t.Errorf("expected holder to be ready after concurrent operations")
	}
}
