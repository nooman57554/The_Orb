package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/middleware"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockAuthzRepo struct {
	hasPlatformPermission func(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
	hasTenantPermission   func(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error)
	userBelongsToTenant   func(ctx context.Context, userID, tenantID uuid.UUID) (bool, error)
	getTenantRole         func(ctx context.Context, userID, tenantID uuid.UUID) (*model.Role, error)
	countActiveAdmins     func(ctx context.Context, tenantID uuid.UUID) (int, error)
	isUserActive          func(ctx context.Context, userID uuid.UUID) (bool, error)
}

func (m *mockAuthzRepo) HasPlatformPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	if m.hasPlatformPermission != nil {
		return m.hasPlatformPermission(ctx, userID, permission)
	}
	return false, nil
}

func (m *mockAuthzRepo) HasTenantPermission(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error) {
	if m.hasTenantPermission != nil {
		return m.hasTenantPermission(ctx, userID, tenantID, permission)
	}
	return false, nil
}

func (m *mockAuthzRepo) UserBelongsToTenant(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	if m.userBelongsToTenant != nil {
		return m.userBelongsToTenant(ctx, userID, tenantID)
	}
	return false, nil
}

func (m *mockAuthzRepo) GetTenantRole(ctx context.Context, userID, tenantID uuid.UUID) (*model.Role, error) {
	if m.getTenantRole != nil {
		return m.getTenantRole(ctx, userID, tenantID)
	}
	return nil, nil
}

func (m *mockAuthzRepo) CountActiveTenantAdmins(ctx context.Context, tenantID uuid.UUID) (int, error) {
	if m.countActiveAdmins != nil {
		return m.countActiveAdmins(ctx, tenantID)
	}
	return 0, nil
}

func (m *mockAuthzRepo) IsUserActive(ctx context.Context, userID uuid.UUID) (bool, error) {
	if m.isUserActive != nil {
		return m.isUserActive(ctx, userID)
	}
	return true, nil
}

func TestAuthorizer_RequirePlatform(t *testing.T) {
	userID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	sessionID := uuid.MustParse("018f0000-0000-7000-8000-000000000002")

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	t.Run("missing policy permission fails closed with 500", func(t *testing.T) {
		repo := &mockAuthzRepo{}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequirePlatform("", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		repo := &mockAuthzRepo{}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequirePlatform("user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("forbidden request returns 403", func(t *testing.T) {
		repo := &mockAuthzRepo{
			hasPlatformPermission: func(ctx context.Context, u uuid.UUID, p string) (bool, error) {
				return false, nil
			},
		}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequirePlatform("user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.MustParse("018f0000-0000-7000-8000-000000000004"),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("database error fails closed with 500", func(t *testing.T) {
		repo := &mockAuthzRepo{
			hasPlatformPermission: func(ctx context.Context, u uuid.UUID, p string) (bool, error) {
				return false, errors.New("connection failed")
			},
		}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequirePlatform("user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.MustParse("018f0000-0000-7000-8000-000000000004"),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("authorized request passes through with 200", func(t *testing.T) {
		repo := &mockAuthzRepo{
			hasPlatformPermission: func(ctx context.Context, u uuid.UUID, p string) (bool, error) {
				return true, nil
			},
		}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequirePlatform("user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.MustParse("018f0000-0000-7000-8000-000000000004"),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})
}

func TestAuthorizer_RequireTenant(t *testing.T) {
	userID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	sessionID := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	tenantID := uuid.MustParse("018f0000-0000-7000-8000-000000000003")

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	t.Run("missing tenant route parameter returns 400", func(t *testing.T) {
		repo := &mockAuthzRepo{}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequireTenant("tenantID", "user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("malformed tenant UUID returns 400", func(t *testing.T) {
		repo := &mockAuthzRepo{}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequireTenant("tenantID", "user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		req.SetPathValue("tenantID", "invalid-uuid")
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		repo := &mockAuthzRepo{}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequireTenant("tenantID", "user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		req.SetPathValue("tenantID", tenantID.String())
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("forbidden tenant request returns 403", func(t *testing.T) {
		repo := &mockAuthzRepo{
			hasTenantPermission: func(ctx context.Context, u, tid uuid.UUID, p string) (bool, error) {
				return false, nil
			},
		}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequireTenant("tenantID", "user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		req.SetPathValue("tenantID", tenantID.String())
		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.MustParse("018f0000-0000-7000-8000-000000000004"),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("database error in tenant authorization fails closed with 500", func(t *testing.T) {
		repo := &mockAuthzRepo{
			hasTenantPermission: func(ctx context.Context, u, tid uuid.UUID, p string) (bool, error) {
				return false, errors.New("db error")
			},
		}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequireTenant("tenantID", "user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		req.SetPathValue("tenantID", tenantID.String())
		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.MustParse("018f0000-0000-7000-8000-000000000004"),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("authorized tenant request succeeds with 200", func(t *testing.T) {
		repo := &mockAuthzRepo{
			hasTenantPermission: func(ctx context.Context, u, tid uuid.UUID, p string) (bool, error) {
				return true, nil
			},
		}
		svc, _ := service.NewAuthorizationService(repo)
		authorizer, _ := middleware.NewAuthorizer(svc)

		handler := authorizer.RequireTenant("tenantID", "user.read", dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		req.SetPathValue("tenantID", tenantID.String())
		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.MustParse("018f0000-0000-7000-8000-000000000004"),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})
}
