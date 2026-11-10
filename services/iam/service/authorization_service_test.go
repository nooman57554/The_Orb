package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockEngine struct {
	decideFunc func(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error)
}

func (m *mockEngine) Authorize(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error) {
	if m.decideFunc != nil {
		return m.decideFunc(ctx, req)
	}
	return authorization.Decision{Allowed: true, Reason: authorization.ReasonAllowed}, nil
}

func (m *mockEngine) SnapshotVersion() int64 {
	return 1
}

func (m *mockEngine) SnapshotAge() time.Duration {
	return 0
}

func (m *mockEngine) IsReady() bool {
	return true
}

func TestNewAuthorizationService(t *testing.T) {
	t.Run("nil engine returns error", func(t *testing.T) {
		_, err := service.NewAuthorizationService(nil)
		if err == nil {
			t.Fatal("expected error when engine is nil")
		}
	})

	t.Run("valid engine succeeds", func(t *testing.T) {
		svc, err := service.NewAuthorizationService(&mockEngine{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if svc.Engine() == nil {
			t.Fatal("expected non-nil engine")
		}
	})
}

func TestAuthorizationService_Authorize(t *testing.T) {
	holder := authorization.NewSnapshotHolder()
	engine := authorization.NewLocalEngine(holder, authorization.EngineConfig{
		MaxPolicyAge: 5 * time.Minute,
	})
	svc, err := service.NewAuthorizationService(engine)
	if err != nil {
		t.Fatalf("unexpected error creating service: %v", err)
	}

	userA := uuid.New()
	tenant1 := uuid.New()
	tenant2 := uuid.New()
	adminRoleID := uuid.New()
	userRoleID := uuid.New()

	snap := &authorization.PolicySnapshot{
		Version:   1,
		CreatedAt: time.Now(),
		Users: map[string]authorization.UserPolicy{
			userA.String(): {
				Active: true,
			},
		},
		PlatformAssignments: map[string]string{},
		TenantAssignments: map[string]map[string]string{
			userA.String(): {
				tenant1.String(): userRoleID.String(),
			},
		},
		Roles: map[string]authorization.RolePolicy{
			userRoleID.String(): {
				ID:    userRoleID.String(),
				Scope: authorization.RoleScopeSystemTenant,
				Permissions: []string{
					authorization.PermTenantUserRead,
				},
			},
			adminRoleID.String(): {
				ID:    adminRoleID.String(),
				Scope: authorization.RoleScopePlatform,
				Permissions: []string{
					authorization.PermPlatformTenantList,
				},
			},
		},
		Permissions: map[string]authorization.PermissionDefinition{
			authorization.PermTenantUserRead: {
				Name:  authorization.PermTenantUserRead,
				Scope: authorization.ScopeTenant,
			},
			authorization.PermPlatformTenantList: {
				Name:  authorization.PermPlatformTenantList,
				Scope: authorization.ScopePlatform,
			},
			authorization.PermPlatformUserRead: {
				Name:  authorization.PermPlatformUserRead,
				Scope: authorization.ScopePlatform,
			},
		},
	}

	if err := holder.Set(snap); err != nil {
		t.Fatalf("failed to set snapshot: %v", err)
	}

	principalA := &identity.Principal{
		UserID:    userA,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	t.Run("authorized tenant operation succeeds", func(t *testing.T) {
		req := authorization.AuthorizationRequest{
			Principal:  principalA,
			Permission: authorization.PermTenantUserRead,
			TenantID:   tenant1.String(),
		}
		dec, err := svc.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !dec.Allowed {
			t.Fatalf("expected allowed, got denied: %s", dec.Reason)
		}
	})

	t.Run("cross-tenant access denied", func(t *testing.T) {
		req := authorization.AuthorizationRequest{
			Principal:  principalA,
			Permission: authorization.PermTenantUserRead,
			TenantID:   tenant2.String(),
		}
		dec, err := svc.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dec.Allowed {
			t.Fatal("expected cross-tenant access to be denied")
		}
		if dec.Reason != authorization.ReasonNoTenantRole {
			t.Fatalf("expected ReasonNoTenantRole, got %s", dec.Reason)
		}
	})

	t.Run("self-profile read allowed", func(t *testing.T) {
		req := authorization.AuthorizationRequest{
			Principal:    principalA,
			Permission:   authorization.PermPlatformUserRead,
			ResourceType: "user",
			ResourceID:   userA.String(),
		}
		dec, err := svc.Authorize(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !dec.Allowed {
			t.Fatalf("expected self-profile read to be allowed: %s", dec.Reason)
		}
	})

	t.Run("engine error propagates", func(t *testing.T) {
		expectedErr := errors.New("engine context cancelled")
		errorEngine := &mockEngine{
			decideFunc: func(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error) {
				return authorization.Decision{}, expectedErr
			},
		}
		errSvc, _ := service.NewAuthorizationService(errorEngine)
		_, err := errSvc.Authorize(context.Background(), authorization.AuthorizationRequest{})
		if !errors.Is(err, expectedErr) {
			t.Fatalf("expected %v, got %v", expectedErr, err)
		}
	})
}
