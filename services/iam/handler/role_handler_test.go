package handler_test

import (
	"bytes"
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

type mockRoleRepoForHandler struct {
	roles             map[uuid.UUID]*model.Role
	activeAssignments map[uuid.UUID]bool
}

func (m *mockRoleRepoForHandler) GetByID(ctx context.Context, id uuid.UUID) (*model.Role, error) {
	r, ok := m.roles[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copy := *r
	return &copy, nil
}
func (m *mockRoleRepoForHandler) GetByNameAndScope(ctx context.Context, name, scope string, tenantID *uuid.UUID) (*model.Role, error) {
	return nil, nil
}
func (m *mockRoleRepoForHandler) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.Role, error) {
	var list []model.Role
	for _, r := range m.roles {
		list = append(list, *r)
	}
	return list, nil
}
func (m *mockRoleRepoForHandler) ListPlatform(ctx context.Context) ([]model.Role, error) {
	var list []model.Role
	for _, r := range m.roles {
		if r.Scope == model.RoleScopePlatform {
			list = append(list, *r)
		}
	}
	return list, nil
}
func (m *mockRoleRepoForHandler) CreateCustom(ctx context.Context, role *model.Role, permissionIDs []uuid.UUID) error {
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	m.roles[role.ID] = role
	return nil
}
func (m *mockRoleRepoForHandler) UpdateCustom(ctx context.Context, role *model.Role, permissionIDs []uuid.UUID) error {
	existing, ok := m.roles[role.ID]
	if !ok {
		return repository.ErrNotFound
	}
	if existing.Scope != model.RoleScopeCustomTenant {
		return repository.ErrSystemRoleImmutable
	}
	existing.Name = role.Name
	existing.Description = role.Description
	return nil
}
func (m *mockRoleRepoForHandler) DeleteCustom(ctx context.Context, id, tenantID uuid.UUID) error {
	existing, ok := m.roles[id]
	if !ok {
		return repository.ErrNotFound
	}
	if existing.Scope != model.RoleScopeCustomTenant {
		return repository.ErrSystemRoleImmutable
	}
	if m.activeAssignments[id] {
		return repository.ErrRoleHasAssignments
	}
	delete(m.roles, id)
	return nil
}
func (m *mockRoleRepoForHandler) HasActiveAssignments(ctx context.Context, roleID uuid.UUID) (bool, error) {
	return m.activeAssignments[roleID], nil
}
func (m *mockRoleRepoForHandler) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]model.Permission, error) {
	r, ok := m.roles[roleID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return r.Permissions, nil
}

type mockRoleAssignRepoForHandler struct {
	members       map[uuid.UUID][]model.TenantMemberRecord
	platformRoles map[uuid.UUID]*model.Role
}

func (m *mockRoleAssignRepoForHandler) AssignTenantRole(ctx context.Context, userID, tenantID, roleID uuid.UUID) error {
	return nil
}
func (m *mockRoleAssignRepoForHandler) RemoveTenantRole(ctx context.Context, userID, tenantID uuid.UUID) error {
	return nil
}
func (m *mockRoleAssignRepoForHandler) ListUsersByTenantRole(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error) {
	return m.members[roleID], nil
}
func (m *mockRoleAssignRepoForHandler) AssignPlatformRole(ctx context.Context, userID, roleID uuid.UUID) error {
	if m.platformRoles == nil {
		m.platformRoles = make(map[uuid.UUID]*model.Role)
	}
	m.platformRoles[userID] = &model.Role{ID: roleID, Scope: model.RoleScopePlatform}
	return nil
}
func (m *mockRoleAssignRepoForHandler) RemovePlatformRole(ctx context.Context, userID uuid.UUID) error {
	if m.platformRoles != nil {
		delete(m.platformRoles, userID)
	}
	return nil
}
func (m *mockRoleAssignRepoForHandler) GetPlatformRole(ctx context.Context, userID uuid.UUID) (*model.Role, error) {
	if m.platformRoles != nil {
		if r, ok := m.platformRoles[userID]; ok {
			return r, nil
		}
	}
	return nil, repository.ErrNotFound
}
func (m *mockRoleAssignRepoForHandler) CountPlatformAdmins(ctx context.Context) (int, error) {
	return 2, nil
}

func TestRoleHandler_CreateCustomTenantRole(t *testing.T) {
	authzRepo := newMockAuthzRepository()
	authzService, _ := service.NewAuthorizationService(authzRepo)
	roleRepo := &mockRoleRepoForHandler{roles: make(map[uuid.UUID]*model.Role)}
	permRepo := &mockPermRepoForHandler{}
	roleAssignRepo := &mockRoleAssignRepoForHandler{members: make(map[uuid.UUID][]model.TenantMemberRecord)}
	userRepo := newMockUserRepository()
	roleService, _ := service.NewRoleService(roleRepo, permRepo, roleAssignRepo, authzService, userRepo)

	h := handler.NewRoleHandler(roleService, authzService, roleAssignRepo)

	userID := uuid.New()
	tenantID := uuid.New()
	authzRepo.grantTenant(userID, tenantID, "role.create")

	body, _ := json.Marshal(map[string]any{
		"name":        "SecurityAuditor",
		"description": "Audits access logs",
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/tenants/"+tenantID.String()+"/roles", bytes.NewReader(body))
	req.SetPathValue("tenantID", tenantID.String())
	req = req.WithContext(identity.WithPrincipal(req.Context(), &identity.Principal{UserID: userID, SessionID: uuid.New(), TokenID: uuid.New()}))
	rec := httptest.NewRecorder()

	h.CreateCustomTenantRole(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRoleHandler_DeleteCustomTenantRole_ConflictWhenAssigned(t *testing.T) {
	authzRepo := newMockAuthzRepository()
	authzService, _ := service.NewAuthorizationService(authzRepo)
	roleID := uuid.New()
	tenantID := uuid.New()
	roleRepo := &mockRoleRepoForHandler{
		roles: map[uuid.UUID]*model.Role{
			roleID: {
				ID:       roleID,
				Name:     "ActiveRole",
				Scope:    model.RoleScopeCustomTenant,
				TenantID: &tenantID,
			},
		},
		activeAssignments: map[uuid.UUID]bool{
			roleID: true,
		},
	}
	permRepo := &mockPermRepoForHandler{}
	roleAssignRepo := &mockRoleAssignRepoForHandler{members: make(map[uuid.UUID][]model.TenantMemberRecord)}
	userRepo := newMockUserRepository()
	roleService, _ := service.NewRoleService(roleRepo, permRepo, roleAssignRepo, authzService, userRepo)

	h := handler.NewRoleHandler(roleService, authzService, roleAssignRepo)

	userID := uuid.New()
	authzRepo.grantTenant(userID, tenantID, "role.delete")

	req := httptest.NewRequest(http.MethodDelete, "/v1/tenants/"+tenantID.String()+"/roles/"+roleID.String(), nil)
	req.SetPathValue("tenantID", tenantID.String())
	req.SetPathValue("roleID", roleID.String())
	req = req.WithContext(identity.WithPrincipal(req.Context(), &identity.Principal{UserID: userID, SessionID: uuid.New(), TokenID: uuid.New()}))
	rec := httptest.NewRecorder()

	h.DeleteCustomTenantRole(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected status 409 Conflict, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRoleHandler_PlatformRole_SelfModificationForbidden(t *testing.T) {
	authzRepo := newMockAuthzRepository()
	authzService, _ := service.NewAuthorizationService(authzRepo)
	roleID := uuid.New()
	roleRepo := &mockRoleRepoForHandler{
		roles: map[uuid.UUID]*model.Role{
			roleID: {
				ID:    roleID,
				Name:  "PLATFORM_ADMIN",
				Scope: model.RoleScopePlatform,
			},
		},
	}
	permRepo := &mockPermRepoForHandler{}
	roleAssignRepo := &mockRoleAssignRepoForHandler{
		members:       make(map[uuid.UUID][]model.TenantMemberRecord),
		platformRoles: make(map[uuid.UUID]*model.Role),
	}
	userRepo := newMockUserRepository()
	roleService, _ := service.NewRoleService(roleRepo, permRepo, roleAssignRepo, authzService, userRepo)

	h := handler.NewRoleHandler(roleService, authzService, roleAssignRepo)

	adminID := uuid.New()
	userRepo.Create(context.Background(), &model.User{ID: adminID, Status: "active"})
	authzRepo.grantPlatform(adminID, "role.assign")

	body, _ := json.Marshal(map[string]any{
		"role_id": roleID.String(),
	})

	req := httptest.NewRequest(http.MethodPut, "/v1/users/"+adminID.String()+"/platform-role", bytes.NewReader(body))
	req.SetPathValue("id", adminID.String())
	req = req.WithContext(identity.WithPrincipal(req.Context(), &identity.Principal{UserID: adminID, SessionID: uuid.New(), TokenID: uuid.New()}))
	rec := httptest.NewRecorder()

	h.AssignPlatformRole(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden on self-modification, got %d: %s", rec.Code, rec.Body.String())
	}
}
