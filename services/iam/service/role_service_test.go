package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockRoleRepository struct {
	roles             map[uuid.UUID]*model.Role
	activeAssignments map[uuid.UUID]bool
}

func newMockRoleRepository() *mockRoleRepository {
	return &mockRoleRepository{
		roles:             make(map[uuid.UUID]*model.Role),
		activeAssignments: make(map[uuid.UUID]bool),
	}
}

func (m *mockRoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Role, error) {
	r, ok := m.roles[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copy := *r
	return &copy, nil
}

func (m *mockRoleRepository) GetByNameAndScope(ctx context.Context, name, scope string, tenantID *uuid.UUID) (*model.Role, error) {
	for _, r := range m.roles {
		if r.Name == name && r.Scope == scope {
			if tenantID == nil && r.TenantID == nil {
				copy := *r
				return &copy, nil
			}
			if tenantID != nil && r.TenantID != nil && *tenantID == *r.TenantID {
				copy := *r
				return &copy, nil
			}
		}
	}
	return nil, repository.ErrNotFound
}

func (m *mockRoleRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.Role, error) {
	var list []model.Role
	for _, r := range m.roles {
		if r.Scope == model.RoleScopeSystemTenant || (r.Scope == model.RoleScopeCustomTenant && r.TenantID != nil && *r.TenantID == tenantID) {
			list = append(list, *r)
		}
	}
	return list, nil
}

func (m *mockRoleRepository) ListPlatform(ctx context.Context) ([]model.Role, error) {
	var list []model.Role
	for _, r := range m.roles {
		if r.Scope == model.RoleScopePlatform {
			list = append(list, *r)
		}
	}
	return list, nil
}

func (m *mockRoleRepository) CreateCustom(ctx context.Context, role *model.Role, permissionIDs []uuid.UUID) error {
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	m.roles[role.ID] = role
	return nil
}

func (m *mockRoleRepository) UpdateCustom(ctx context.Context, role *model.Role, permissionIDs []uuid.UUID) error {
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

func (m *mockRoleRepository) DeleteCustom(ctx context.Context, id, tenantID uuid.UUID) error {
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

func (m *mockRoleRepository) HasActiveAssignments(ctx context.Context, roleID uuid.UUID) (bool, error) {
	return m.activeAssignments[roleID], nil
}

func (m *mockRoleRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]model.Permission, error) {
	r, ok := m.roles[roleID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return r.Permissions, nil
}

type mockPermissionRepository struct {
	permissions map[uuid.UUID]model.Permission
}

func newMockPermissionRepository() *mockPermissionRepository {
	return &mockPermissionRepository{
		permissions: make(map[uuid.UUID]model.Permission),
	}
}

func (m *mockPermissionRepository) ListAll(ctx context.Context) ([]model.Permission, error) {
	var list []model.Permission
	for _, p := range m.permissions {
		list = append(list, p)
	}
	return list, nil
}

func (m *mockPermissionRepository) GetByIDs(ctx context.Context, ids []uuid.UUID) ([]model.Permission, error) {
	var list []model.Permission
	for _, id := range ids {
		if p, ok := m.permissions[id]; ok {
			list = append(list, p)
		}
	}
	return list, nil
}

func (m *mockPermissionRepository) GetByName(ctx context.Context, name string) (*model.Permission, error) {
	for _, p := range m.permissions {
		if p.Name == name {
			return &p, nil
		}
	}
	return nil, repository.ErrNotFound
}

func TestRoleService_CreateCustomTenantRole_PrivilegeEscalationPrevented(t *testing.T) {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()

	platformPermID := uuid.New()
	permRepo.permissions[platformPermID] = model.Permission{
		ID:   platformPermID,
		Name: "tenant.create", // platform-only permission
	}

	svc, err := service.NewRoleService(roleRepo, permRepo)
	if err != nil {
		t.Fatalf("failed to create role service: %v", err)
	}

	tenantID := uuid.New()
	_, err = svc.CreateCustomTenantRole(context.Background(), tenantID, "MaliciousRole", "desc", []uuid.UUID{platformPermID})
	if !errors.Is(err, service.ErrPrivilegeEscalation) {
		t.Fatalf("expected ErrPrivilegeEscalation, got %v", err)
	}
}

func TestRoleService_CreateCustomTenantRole_Success(t *testing.T) {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()

	tenantPermID := uuid.New()
	permRepo.permissions[tenantPermID] = model.Permission{
		ID:   tenantPermID,
		Name: "user.read",
	}

	svc, err := service.NewRoleService(roleRepo, permRepo)
	if err != nil {
		t.Fatalf("failed to create role service: %v", err)
	}

	tenantID := uuid.New()
	role, err := svc.CreateCustomTenantRole(context.Background(), tenantID, "Analyst", "Analyst role", []uuid.UUID{tenantPermID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Name != "Analyst" {
		t.Fatalf("expected role name Analyst, got %s", role.Name)
	}
	if role.Scope != model.RoleScopeCustomTenant {
		t.Fatalf("expected custom_tenant scope, got %s", role.Scope)
	}
}

func TestRoleService_DeleteCustomTenantRole_ActiveAssignmentsPrevented(t *testing.T) {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()

	tenantID := uuid.New()
	roleID := uuid.New()
	roleRepo.roles[roleID] = &model.Role{
		ID:       roleID,
		Name:     "CustomAuditor",
		Scope:    model.RoleScopeCustomTenant,
		TenantID: &tenantID,
	}
	roleRepo.activeAssignments[roleID] = true

	svc, err := service.NewRoleService(roleRepo, permRepo)
	if err != nil {
		t.Fatalf("failed to create role service: %v", err)
	}

	err = svc.DeleteCustomTenantRole(context.Background(), tenantID, roleID)
	if !errors.Is(err, repository.ErrRoleHasAssignments) {
		t.Fatalf("expected ErrRoleHasAssignments, got %v", err)
	}
}

func TestRoleService_SystemRoleImmutable(t *testing.T) {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()

	systemRoleID := uuid.New()
	roleRepo.roles[systemRoleID] = &model.Role{
		ID:    systemRoleID,
		Name:  "TENANT_ADMIN_RW",
		Scope: model.RoleScopeSystemTenant,
	}

	svc, err := service.NewRoleService(roleRepo, permRepo)
	if err != nil {
		t.Fatalf("failed to create role service: %v", err)
	}

	tenantID := uuid.New()
	_, err = svc.UpdateCustomTenantRole(context.Background(), tenantID, systemRoleID, "ModifiedName", "desc", nil)
	if !errors.Is(err, repository.ErrSystemRoleImmutable) {
		t.Fatalf("expected ErrSystemRoleImmutable, got %v", err)
	}

	err = svc.DeleteCustomTenantRole(context.Background(), tenantID, systemRoleID)
	if !errors.Is(err, repository.ErrSystemRoleImmutable) {
		t.Fatalf("expected ErrSystemRoleImmutable on delete, got %v", err)
	}
}
