package authorization

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

func TestAuthorizer_Middleware(t *testing.T) {
	holder := NewSnapshotHolder()
	snapshot := makeTestSnapshot(1, time.Now())
	if err := holder.Set(snapshot); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}

	engine := NewLocalEngine(holder)
	authorizer, err := NewAuthorizer(engine)
	if err != nil {
		t.Fatalf("create authorizer: %v", err)
	}

	adminUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000010")
	tenantUserUUID := uuid.MustParse("01a00000-0000-7000-8000-000000000020")
	tenantA := "01a00000-0000-7000-8000-000000000001"

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	t.Run("401 Unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
		rec := httptest.NewRecorder()

		authorizer.Require(PermPlatformTenantList)(okHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("403 Forbidden platform permission for non-platform admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
		principal := &identity.Principal{
			UserID:    tenantUserUUID,
			SessionID: uuid.New(),
			TokenID:   uuid.New(),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		authorizer.Require(PermPlatformTenantList)(okHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("200 OK Platform Permission Allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
		principal := &identity.Principal{
			UserID:    adminUUID,
			SessionID: uuid.New(),
			TokenID:   uuid.New(),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		authorizer.Require(PermPlatformTenantList)(okHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("200 OK Tenant Permission Allowed with RouteParam", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/tenants/"+tenantA+"/users", nil)
		req.SetPathValue("tenantID", tenantA)

		principal := &identity.Principal{
			UserID:    tenantUserUUID,
			SessionID: uuid.New(),
			TokenID:   uuid.New(),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		authorizer.Require(PermTenantUserCreate, RouteParam("tenantID"))(okHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("400 Bad Request missing tenant route parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/v1/tenants//users", nil)
		// Missing path value
		principal := &identity.Principal{
			UserID:    tenantUserUUID,
			SessionID: uuid.New(),
			TokenID:   uuid.New(),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		authorizer.Require(PermTenantUserCreate, RouteParam("tenantID"))(okHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", rec.Code)
		}
	})

	t.Run("503 Service Unavailable when policy unavailable", func(t *testing.T) {
		emptyHolder := NewSnapshotHolder()
		emptyAuthorizer, _ := NewAuthorizer(NewLocalEngine(emptyHolder))

		req := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
		principal := &identity.Principal{
			UserID:    adminUUID,
			SessionID: uuid.New(),
			TokenID:   uuid.New(),
		}
		req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
		rec := httptest.NewRecorder()

		emptyAuthorizer.Require(PermPlatformTenantList)(okHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d", rec.Code)
		}
	})
}
