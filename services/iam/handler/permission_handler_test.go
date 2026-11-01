package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockPermRepoForHandler struct {
	perms []model.Permission
}

func (m *mockPermRepoForHandler) ListAll(ctx context.Context) ([]model.Permission, error) {
	return m.perms, nil
}
func (m *mockPermRepoForHandler) GetByIDs(ctx context.Context, ids []uuid.UUID) ([]model.Permission, error) {
	return nil, nil
}
func (m *mockPermRepoForHandler) GetByName(ctx context.Context, name string) (*model.Permission, error) {
	for _, p := range m.perms {
		if p.Name == name {
			return &p, nil
		}
	}
	return nil, repository.ErrNotFound
}

func TestPermissionHandler_ListPermissions_Success(t *testing.T) {
	authzRepo := newMockAuthzRepository()
	authzService, _ := service.NewAuthorizationService(authzRepo)

	userID := uuid.New()
	authzRepo.grantPlatform(userID, "permission.read")

	permRepo := &mockPermRepoForHandler{
		perms: []model.Permission{
			{ID: uuid.New(), Name: "user.read", Scope: "tenant", Description: "Read users"},
			{ID: uuid.New(), Name: "tenant.create", Scope: "platform", Description: "Create tenants"},
		},
	}

	h := handler.NewPermissionHandler(permRepo, authzService)

	req := httptest.NewRequest(http.MethodGet, "/v1/permissions", nil)
	principal := &identity.Principal{UserID: userID, SessionID: uuid.New(), TokenID: uuid.New()}
	req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
	rec := httptest.NewRecorder()

	h.ListPermissions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Permissions []struct {
			Name           string `json:"name"`
			TenantEligible bool   `json:"tenant_eligible"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.Permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(resp.Permissions))
	}
	for _, p := range resp.Permissions {
		if p.Name == "user.read" && !p.TenantEligible {
			t.Fatalf("expected user.read to be tenant eligible")
		}
		if p.Name == "tenant.create" && p.TenantEligible {
			t.Fatalf("expected tenant.create to NOT be tenant eligible")
		}
	}
}

func TestPermissionHandler_ListPermissions_Forbidden(t *testing.T) {
	authzRepo := newMockAuthzRepository()
	authzService, _ := service.NewAuthorizationService(authzRepo)
	permRepo := &mockPermRepoForHandler{}

	h := handler.NewPermissionHandler(permRepo, authzService)

	req := httptest.NewRequest(http.MethodGet, "/v1/permissions", nil)
	principal := &identity.Principal{UserID: uuid.New(), SessionID: uuid.New(), TokenID: uuid.New()}
	req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
	rec := httptest.NewRecorder()

	h.ListPermissions(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}
