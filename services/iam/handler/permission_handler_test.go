package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
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

type mockRoleRepoForPermHandler struct {
	repository.RoleRepository
}

func (m *mockRoleRepoForPermHandler) ListPlatform(ctx context.Context) ([]model.Role, error) {
	return nil, nil
}

func TestPermissionHandler_ListPermissions_Success(t *testing.T) {
	userID := uuid.New()
	roleID := uuid.New()

	holder := authorization.NewSnapshotHolder()
	engine := authorization.NewLocalEngine(holder)

	snap := &authorization.PolicySnapshot{
		Version:   1,
		CreatedAt: time.Now(),
		Users: map[string]authorization.UserPolicy{
			userID.String(): {Active: true},
		},
		PlatformAssignments: map[string]string{
			userID.String(): roleID.String(),
		},
		TenantAssignments: map[string]map[string]string{},
		Roles: map[string]authorization.RolePolicy{
			roleID.String(): {
				ID:          roleID.String(),
				Scope:       authorization.RoleScopePlatform,
				Permissions: []string{authorization.PermPlatformRoleRead},
			},
		},
		Permissions: map[string]authorization.PermissionDefinition{
			authorization.PermPlatformRoleRead: {Name: authorization.PermPlatformRoleRead, Scope: authorization.ScopePlatform},
		},
	}
	_ = holder.Set(snap)

	permRepo := &mockPermRepoForHandler{
		perms: []model.Permission{
			{ID: uuid.New(), Name: authorization.PermTenantUserRead, Scope: "tenant", Description: "Read users"},
			{ID: uuid.New(), Name: authorization.PermPlatformTenantCreate, Scope: "platform", Description: "Create tenants"},
		},
	}

	roleService, _ := service.NewRoleService(&mockRoleRepoForPermHandler{}, permRepo)
	h := handler.NewPermissionHandler(roleService, engine)

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
		if p.Name == authorization.PermTenantUserRead && !p.TenantEligible {
			t.Fatalf("expected PermTenantUserRead to be tenant eligible")
		}
		if p.Name == authorization.PermPlatformTenantCreate && p.TenantEligible {
			t.Fatalf("expected PermPlatformTenantCreate to NOT be tenant eligible")
		}
	}
}

func TestPermissionHandler_ListPermissions_Forbidden(t *testing.T) {
	holder := authorization.NewSnapshotHolder()
	engine := authorization.NewLocalEngine(holder)

	// Empty snapshot - user has no permissions
	_ = holder.Set(&authorization.PolicySnapshot{
		Version:             1,
		CreatedAt:           time.Now(),
		Users:               map[string]authorization.UserPolicy{},
		PlatformAssignments: map[string]string{},
		TenantAssignments:   map[string]map[string]string{},
		Roles:               map[string]authorization.RolePolicy{},
		Permissions: map[string]authorization.PermissionDefinition{
			authorization.PermPlatformRoleRead: {Name: authorization.PermPlatformRoleRead, Scope: authorization.ScopePlatform},
		},
	})

	permRepo := &mockPermRepoForHandler{}
	roleService, _ := service.NewRoleService(&mockRoleRepoForPermHandler{}, permRepo)
	h := handler.NewPermissionHandler(roleService, engine)

	req := httptest.NewRequest(http.MethodGet, "/v1/permissions", nil)
	principal := &identity.Principal{UserID: uuid.New(), SessionID: uuid.New(), TokenID: uuid.New()}
	req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
	rec := httptest.NewRecorder()

	h.ListPermissions(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rec.Code)
	}
}
