package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/middleware"
)

type mockEngine struct {
	authorize func(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error)
	version   int64
	age       time.Duration
	ready     bool
}

func (m *mockEngine) Authorize(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error) {
	if m.authorize != nil {
		return m.authorize(ctx, req)
	}
	return authorization.Decision{Allowed: true, Reason: authorization.ReasonAllowed}, nil
}

func (m *mockEngine) SnapshotVersion() int64 {
	return m.version
}

func (m *mockEngine) SnapshotAge() time.Duration {
	return m.age
}

func (m *mockEngine) IsReady() bool {
	return m.ready
}

func TestAuthorizer_Require(t *testing.T) {
	userID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	sessionID := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	tenantID := uuid.MustParse("018f0000-0000-7000-8000-000000000003")

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	t.Run("missing permission fails closed with 500", func(t *testing.T) {
		engine := &mockEngine{ready: true}
		authorizer, _ := middleware.NewAuthorizer(engine)

		handler := authorizer.Require("", nil)(dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("unknown permission fails closed with 500", func(t *testing.T) {
		engine := &mockEngine{ready: true}
		authorizer, _ := middleware.NewAuthorizer(engine)

		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.New(),
		}
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler := authorizer.Require("nonexistent.permission")(dummyHandler)
		handler(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rec.Code)
		}
	})

	t.Run("unauthenticated request returns 401", func(t *testing.T) {
		engine := &mockEngine{ready: true}
		authorizer, _ := middleware.NewAuthorizer(engine)

		handler := authorizer.Require(authorization.PermPlatformTenantList)(dummyHandler)
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()

		handler(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("forbidden platform permission returns 403", func(t *testing.T) {
		engine := &mockEngine{
			ready: true,
			authorize: func(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error) {
				return authorization.Decision{
					Allowed: false,
					Reason:  authorization.ReasonNoPlatformRole,
				}, nil
			},
		}
		authorizer, _ := middleware.NewAuthorizer(engine)

		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.New(),
		}
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler := authorizer.Require(authorization.PermPlatformTenantList)(dummyHandler)
		handler(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("allowed platform permission returns 200", func(t *testing.T) {
		engine := &mockEngine{
			ready: true,
			authorize: func(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error) {
				return authorization.Decision{
					Allowed: true,
					Reason:  authorization.ReasonAllowed,
				}, nil
			},
		}
		authorizer, _ := middleware.NewAuthorizer(engine)

		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.New(),
		}
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler := authorizer.Require(authorization.PermPlatformTenantList)(dummyHandler)
		handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("tenant permission with RouteParam resolver returns 200 when allowed", func(t *testing.T) {
		engine := &mockEngine{
			ready: true,
			authorize: func(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error) {
				if req.TenantID != tenantID.String() {
					t.Errorf("expected tenantID %s, got %s", tenantID.String(), req.TenantID)
				}
				return authorization.Decision{
					Allowed: true,
					Reason:  authorization.ReasonAllowed,
				}, nil
			},
		}
		authorizer, _ := middleware.NewAuthorizer(engine)

		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.New(),
		}
		req := httptest.NewRequest("POST", "/v1/tenants/"+tenantID.String()+"/users", nil)
		req.SetPathValue("tenantID", tenantID.String())
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler := authorizer.Require(authorization.PermTenantUserCreate, authorization.RouteParam("tenantID"))(dummyHandler)
		handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("tenant permission missing route param returns 400", func(t *testing.T) {
		engine := &mockEngine{ready: true}
		authorizer, _ := middleware.NewAuthorizer(engine)

		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.New(),
		}
		req := httptest.NewRequest("POST", "/v1/tenants//users", nil)
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler := authorizer.Require(authorization.PermTenantUserCreate, authorization.RouteParam("tenantID"))(dummyHandler)
		handler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("policy unavailable fails closed with 503", func(t *testing.T) {
		engine := &mockEngine{
			ready: false,
			authorize: func(ctx context.Context, req authorization.AuthorizationRequest) (authorization.Decision, error) {
				return authorization.Decision{}, authorization.ErrPolicyUnavailable
			},
		}
		authorizer, _ := middleware.NewAuthorizer(engine)

		principal := &identity.Principal{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   uuid.New(),
		}
		req := httptest.NewRequest("GET", "/test", nil)
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		handler := authorizer.Require(authorization.PermPlatformTenantList)(dummyHandler)
		handler(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", rec.Code)
		}
	})
}
