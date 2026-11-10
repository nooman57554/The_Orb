package service_test

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

// mockAuthorizationRepository implements repository.AuthorizationRepository
type mockAuthorizationRepository struct {
	platformPerms map[uuid.UUID]map[string]bool
	tenantPerms   map[uuid.UUID]map[uuid.UUID]map[string]bool
	tenantRoles   map[uuid.UUID]map[uuid.UUID]*model.Role
	userActive    map[uuid.UUID]bool
	forceError    bool
}

func newMockAuthorizationRepository() *mockAuthorizationRepository {
	return &mockAuthorizationRepository{
		platformPerms: make(map[uuid.UUID]map[string]bool),
		tenantPerms:   make(map[uuid.UUID]map[uuid.UUID]map[string]bool),
		tenantRoles:   make(map[uuid.UUID]map[uuid.UUID]*model.Role),
		userActive:    make(map[uuid.UUID]bool),
	}
}

func (m *mockAuthorizationRepository) grantPlatform(userID uuid.UUID, permission string) {
	if m.platformPerms[userID] == nil {
		m.platformPerms[userID] = make(map[string]bool)
	}
	m.platformPerms[userID][permission] = true
}

func (m *mockAuthorizationRepository) grantTenant(userID, tenantID uuid.UUID, permission string) {
	if m.tenantPerms[userID] == nil {
		m.tenantPerms[userID] = make(map[uuid.UUID]map[string]bool)
	}
	if m.tenantPerms[userID][tenantID] == nil {
		m.tenantPerms[userID][tenantID] = make(map[string]bool)
	}
	m.tenantPerms[userID][tenantID][permission] = true
}

func (m *mockAuthorizationRepository) HasPlatformPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused")
	}
	if m.platformPerms[userID] != nil && m.platformPerms[userID][permission] {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthorizationRepository) HasTenantPermission(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused")
	}
	if m.tenantPerms[userID] != nil && m.tenantPerms[userID][tenantID] != nil && m.tenantPerms[userID][tenantID][permission] {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthorizationRepository) UserBelongsToTenant(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused")
	}
	if m.tenantRoles[userID] != nil && m.tenantRoles[userID][tenantID] != nil {
		return true, nil
	}
	if m.tenantPerms[userID] != nil && m.tenantPerms[userID][tenantID] != nil {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthorizationRepository) GetTenantRole(ctx context.Context, userID, tenantID uuid.UUID) (*model.Role, error) {
	if m.forceError {
		return nil, errors.New("database connection refused")
	}
	if m.tenantRoles != nil && m.tenantRoles[userID] != nil && m.tenantRoles[userID][tenantID] != nil {
		return m.tenantRoles[userID][tenantID], nil
	}
	return nil, repository.ErrNotFound
}

func (m *mockAuthorizationRepository) IsUserActive(ctx context.Context, userID uuid.UUID) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused")
	}
	if active, ok := m.userActive[userID]; ok {
		return active, nil
	}
	return true, nil
}

// mockRoleAssignmentRepo implements repository.RoleAssignmentRepository
type mockRoleAssignmentRepo struct {
	tenantAssignments     map[uuid.UUID]map[uuid.UUID]uuid.UUID // userID -> tenantID -> roleID
	platformAssignments   map[uuid.UUID]uuid.UUID               // userID -> roleID
	roles                 map[uuid.UUID]*model.Role
	users                 map[uuid.UUID]*model.User
	activeTenantAdmins    map[uuid.UUID]int
	platformAdminCount    int
	assignTenantRole      func(ctx context.Context, userID, tenantID, roleID uuid.UUID) error
	removeTenantRole      func(ctx context.Context, userID, tenantID uuid.UUID) error
	listUsersByTenantRole func(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error)
	assignPlatformRole    func(ctx context.Context, userID, roleID uuid.UUID) error
	removePlatformRole    func(ctx context.Context, userID uuid.UUID) error
	getPlatformRole       func(ctx context.Context, userID uuid.UUID) (*model.Role, error)
	countPlatformAdmins   func(ctx context.Context) (int, error)
}

func newMockRoleAssignmentRepo() *mockRoleAssignmentRepo {
	return &mockRoleAssignmentRepo{
		tenantAssignments:   make(map[uuid.UUID]map[uuid.UUID]uuid.UUID),
		platformAssignments: make(map[uuid.UUID]uuid.UUID),
		roles:               make(map[uuid.UUID]*model.Role),
		users:               make(map[uuid.UUID]*model.User),
		activeTenantAdmins:  make(map[uuid.UUID]int),
		platformAdminCount:  1,
	}
}

func (m *mockRoleAssignmentRepo) AssignTenantRole(ctx context.Context, userID, tenantID, roleID uuid.UUID) error {
	if m.assignTenantRole != nil {
		return m.assignTenantRole(ctx, userID, tenantID, roleID)
	}
	if m.tenantAssignments[userID] == nil {
		m.tenantAssignments[userID] = make(map[uuid.UUID]uuid.UUID)
	}
	m.tenantAssignments[userID][tenantID] = roleID
	return nil
}

func (m *mockRoleAssignmentRepo) RemoveTenantRole(ctx context.Context, userID, tenantID uuid.UUID) error {
	if m.removeTenantRole != nil {
		return m.removeTenantRole(ctx, userID, tenantID)
	}
	if m.tenantAssignments[userID] != nil {
		delete(m.tenantAssignments[userID], tenantID)
	}
	return nil
}

func (m *mockRoleAssignmentRepo) GetTenantRole(ctx context.Context, userID, tenantID uuid.UUID) (*model.Role, error) {
	if m.tenantAssignments[userID] != nil {
		if roleID, ok := m.tenantAssignments[userID][tenantID]; ok {
			if r, exists := m.roles[roleID]; exists {
				return r, nil
			}
			return &model.Role{ID: roleID, Scope: model.RoleScopeSystemTenant, Name: "TENANT_USER"}, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (m *mockRoleAssignmentRepo) UserBelongsToTenant(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	if m.tenantAssignments[userID] != nil {
		_, ok := m.tenantAssignments[userID][tenantID]
		return ok, nil
	}
	return false, nil
}

func (m *mockRoleAssignmentRepo) ListUsersByTenantRole(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error) {
	if m.listUsersByTenantRole != nil {
		return m.listUsersByTenantRole(ctx, tenantID, roleID)
	}
	var records []model.TenantMemberRecord
	for uID, tenants := range m.tenantAssignments {
		if rID, ok := tenants[tenantID]; ok && rID == roleID {
			records = append(records, model.TenantMemberRecord{
				UserID: uID,
				RoleID: roleID,
			})
		}
	}
	return records, nil
}

func (m *mockRoleAssignmentRepo) CountActiveTenantAdmins(ctx context.Context, tenantID uuid.UUID) (int, error) {
	if count, ok := m.activeTenantAdmins[tenantID]; ok {
		return count, nil
	}
	return 1, nil
}

func (m *mockRoleAssignmentRepo) AssignPlatformRole(ctx context.Context, userID, roleID uuid.UUID) error {
	if m.assignPlatformRole != nil {
		return m.assignPlatformRole(ctx, userID, roleID)
	}
	m.platformAssignments[userID] = roleID
	return nil
}

func (m *mockRoleAssignmentRepo) RemovePlatformRole(ctx context.Context, userID uuid.UUID) error {
	if m.removePlatformRole != nil {
		return m.removePlatformRole(ctx, userID)
	}
	delete(m.platformAssignments, userID)
	return nil
}

func (m *mockRoleAssignmentRepo) GetPlatformRole(ctx context.Context, userID uuid.UUID) (*model.Role, error) {
	if m.getPlatformRole != nil {
		return m.getPlatformRole(ctx, userID)
	}
	if roleID, ok := m.platformAssignments[userID]; ok {
		if r, exists := m.roles[roleID]; exists {
			return r, nil
		}
		return &model.Role{ID: roleID, Scope: model.RoleScopePlatform, Name: "PLATFORM_ADMIN"}, nil
	}
	return nil, repository.ErrNotFound
}

func (m *mockRoleAssignmentRepo) CountPlatformAdmins(ctx context.Context) (int, error) {
	if m.countPlatformAdmins != nil {
		return m.countPlatformAdmins(ctx)
	}
	return m.platformAdminCount, nil
}

// mockRoleRepository implements repository.RoleRepository
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

// mockUserRepository implements repository.UserRepository
type mockUserRepository struct {
	users                    map[uuid.UUID]*model.User
	CreateWithTenantRoleFunc func(ctx context.Context, user *model.User, tenantID, roleID uuid.UUID) error
}

func newMockUserRepository() *mockUserRepository {
	return &mockUserRepository{users: make(map[uuid.UUID]*model.User)}
}

func (m *mockUserRepository) Create(ctx context.Context, user *model.User) error {
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) CreateWithTenantRole(ctx context.Context, user *model.User, tenantID, roleID uuid.UUID) error {
	if m.CreateWithTenantRoleFunc != nil {
		return m.CreateWithTenantRoleFunc(ctx, user, tenantID, roleID)
	}
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	for _, u := range m.users {
		if strings.EqualFold(u.Email, user.Email) {
			return repository.ErrDuplicateEmail
		}
	}
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	if u, ok := m.users[id]; ok {
		return u, nil
	}
	return nil, repository.ErrNotFound
}

func (m *mockUserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	for _, u := range m.users {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (m *mockUserRepository) GetByIDInTenant(ctx context.Context, userID, tenantID uuid.UUID) (*model.TenantMemberRecord, error) {
	u, ok := m.users[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return &model.TenantMemberRecord{
		UserID: u.ID,
		Email:  u.Email,
		Status: u.Status,
	}, nil
}

func (m *mockUserRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID, offset, limit int) ([]model.TenantMemberRecord, int, error) {
	var records []model.TenantMemberRecord
	for _, u := range m.users {
		records = append(records, model.TenantMemberRecord{
			UserID: u.ID,
			Email:  u.Email,
			Status: u.Status,
		})
	}
	return records, len(records), nil
}

func (m *mockUserRepository) Update(ctx context.Context, user *model.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	if u, ok := m.users[id]; ok {
		u.Status = status
		return nil
	}
	return repository.ErrNotFound
}

// mockTenantRepository implements repository.TenantRepository
type mockTenantRepository struct {
	tenants map[uuid.UUID]*model.Tenant
}

func newMockTenantRepository() *mockTenantRepository {
	return &mockTenantRepository{tenants: make(map[uuid.UUID]*model.Tenant)}
}

func (m *mockTenantRepository) Create(ctx context.Context, tenant *model.Tenant) error {
	if tenant.ID == uuid.Nil {
		tenant.ID = uuid.New()
	}
	m.tenants[tenant.ID] = tenant
	return nil
}

func (m *mockTenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	if t, ok := m.tenants[id]; ok {
		return t, nil
	}
	return nil, repository.ErrNotFound
}

func (m *mockTenantRepository) GetBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	for _, t := range m.tenants {
		if t.Slug == slug {
			return t, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (m *mockTenantRepository) List(ctx context.Context, offset, limit int) ([]model.Tenant, int, error) {
	var list []model.Tenant
	for _, t := range m.tenants {
		list = append(list, *t)
	}
	return list, len(list), nil
}

func (m *mockTenantRepository) Update(ctx context.Context, tenant *model.Tenant) error {
	m.tenants[tenant.ID] = tenant
	return nil
}

func (m *mockTenantRepository) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	if t, ok := m.tenants[id]; ok {
		t.Status = status
		return nil
	}
	return repository.ErrNotFound
}

// mockPermissionRepository implements repository.PermissionRepository
type mockPermissionRepository struct {
	permissions map[uuid.UUID]model.Permission
}

func newMockPermissionRepository() *mockPermissionRepository {
	return &mockPermissionRepository{permissions: make(map[uuid.UUID]model.Permission)}
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
