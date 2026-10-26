package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockTenantRepoForUserService struct {
	tenants map[uuid.UUID]*model.Tenant
}

func newMockTenantRepoForUserService() *mockTenantRepoForUserService {
	return &mockTenantRepoForUserService{tenants: make(map[uuid.UUID]*model.Tenant)}
}

func (m *mockTenantRepoForUserService) Create(ctx context.Context, tenant *model.Tenant) error {
	m.tenants[tenant.ID] = tenant
	return nil
}
func (m *mockTenantRepoForUserService) GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	t, ok := m.tenants[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return t, nil
}
func (m *mockTenantRepoForUserService) GetBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	for _, t := range m.tenants {
		if t.Slug == slug {
			return t, nil
		}
	}
	return nil, repository.ErrNotFound
}
func (m *mockTenantRepoForUserService) List(ctx context.Context, offset, limit int) ([]model.Tenant, int, error) {
	var list []model.Tenant
	for _, t := range m.tenants {
		list = append(list, *t)
	}
	return list, len(list), nil
}
func (m *mockTenantRepoForUserService) Update(ctx context.Context, tenant *model.Tenant) error {
	m.tenants[tenant.ID] = tenant
	return nil
}
func (m *mockTenantRepoForUserService) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	t, ok := m.tenants[id]
	if !ok {
		return repository.ErrNotFound
	}
	t.Status = status
	return nil
}

type mockUserRepoForUserService struct {
	users   map[uuid.UUID]*model.User
	members map[uuid.UUID]map[uuid.UUID]uuid.UUID // tenantID -> userID -> roleID
}

func newMockUserRepoForUserService() *mockUserRepoForUserService {
	return &mockUserRepoForUserService{
		users:   make(map[uuid.UUID]*model.User),
		members: make(map[uuid.UUID]map[uuid.UUID]uuid.UUID),
	}
}

func (m *mockUserRepoForUserService) Create(ctx context.Context, user *model.User) error {
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	m.users[user.ID] = user
	return nil
}
func (m *mockUserRepoForUserService) CreateWithTenantRole(ctx context.Context, user *model.User, tenantID, roleID uuid.UUID) error {
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	m.users[user.ID] = user
	if m.members[tenantID] == nil {
		m.members[tenantID] = make(map[uuid.UUID]uuid.UUID)
	}
	m.members[tenantID][user.ID] = roleID
	return nil
}
func (m *mockUserRepoForUserService) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return u, nil
}
func (m *mockUserRepoForUserService) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	for _, u := range m.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, repository.ErrNotFound
}
func (m *mockUserRepoForUserService) GetByIDInTenant(ctx context.Context, userID, tenantID uuid.UUID) (*model.TenantMemberRecord, error) {
	u, ok := m.users[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	roleID, ok := m.members[tenantID][userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return &model.TenantMemberRecord{
		UserID:    u.ID,
		Email:     u.Email,
		Status:    u.Status,
		RoleID:    roleID,
		RoleName:  "TEST_ROLE",
		RoleScope: model.RoleScopeSystemTenant,
		JoinedAt:  time.Now(),
	}, nil
}
func (m *mockUserRepoForUserService) ListByTenant(ctx context.Context, tenantID uuid.UUID, offset, limit int) ([]model.TenantMemberRecord, int, error) {
	var list []model.TenantMemberRecord
	for uID, rID := range m.members[tenantID] {
		u := m.users[uID]
		list = append(list, model.TenantMemberRecord{
			UserID:    u.ID,
			Email:     u.Email,
			Status:    u.Status,
			RoleID:    rID,
			RoleName:  "TEST_ROLE",
			RoleScope: model.RoleScopeSystemTenant,
			JoinedAt:  time.Now(),
		})
	}
	return list, len(list), nil
}
func (m *mockUserRepoForUserService) Update(ctx context.Context, user *model.User) error {
	m.users[user.ID] = user
	return nil
}
func (m *mockUserRepoForUserService) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	u, ok := m.users[id]
	if !ok {
		return repository.ErrNotFound
	}
	u.Status = status
	return nil
}

type mockRoleAssignRepo struct {
	assignments map[uuid.UUID]map[uuid.UUID]uuid.UUID // tenantID -> userID -> roleID
}

func newMockRoleAssignRepo() *mockRoleAssignRepo {
	return &mockRoleAssignRepo{
		assignments: make(map[uuid.UUID]map[uuid.UUID]uuid.UUID),
	}
}

func (m *mockRoleAssignRepo) AssignTenantRole(ctx context.Context, userID, tenantID, roleID uuid.UUID) error {
	if m.assignments[tenantID] == nil {
		m.assignments[tenantID] = make(map[uuid.UUID]uuid.UUID)
	}
	m.assignments[tenantID][userID] = roleID
	return nil
}
func (m *mockRoleAssignRepo) RemoveTenantRole(ctx context.Context, userID, tenantID uuid.UUID) error {
	if m.assignments[tenantID] != nil {
		delete(m.assignments[tenantID], userID)
	}
	return nil
}
func (m *mockRoleAssignRepo) ListUsersByTenantRole(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error) {
	return nil, nil
}
func (m *mockRoleAssignRepo) AssignPlatformRole(ctx context.Context, userID, roleID uuid.UUID) error {
	return nil
}
func (m *mockRoleAssignRepo) RemovePlatformRole(ctx context.Context, userID uuid.UUID) error {
	return nil
}
func (m *mockRoleAssignRepo) CountPlatformAdmins(ctx context.Context) (int, error) {
	return 1, nil
}

type mockSessionRepoForUserService struct {
	revokedUsers map[uuid.UUID]bool
}

func (m *mockSessionRepoForUserService) Create(ctx context.Context, session *model.Session, tokenHash string) error {
	return nil
}
func (m *mockSessionRepoForUserService) GetByRefreshTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	return nil, nil
}
func (m *mockSessionRepoForUserService) GetByPreviousTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	return nil, nil
}
func (m *mockSessionRepoForUserService) RotateRefreshToken(ctx context.Context, oldTokenHash, newTokenHash string) (*model.Session, error) {
	return nil, nil
}
func (m *mockSessionRepoForUserService) RevokeByRefreshTokenHash(ctx context.Context, tokenHash string) error {
	return nil
}
func (m *mockSessionRepoForUserService) Revoke(ctx context.Context, sessionID uuid.UUID) error {
	return nil
}
func (m *mockSessionRepoForUserService) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	m.revokedUsers[userID] = true
	return nil
}
func (m *mockSessionRepoForUserService) IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	return true, nil
}

func TestTenantUserService_LastAdminProtection(t *testing.T) {
	userRepo := newMockUserRepoForUserService()
	tenantRepo := newMockTenantRepoForUserService()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignRepo()
	authzRepo := newMockAuthorizationRepository()
	sessionRepo := &mockSessionRepoForUserService{revokedUsers: make(map[uuid.UUID]bool)}

	tenantID := uuid.New()
	tenantRepo.tenants[tenantID] = &model.Tenant{ID: tenantID, Status: "active"}

	adminRoleID := uuid.New()
	adminRole := &model.Role{
		ID:    adminRoleID,
		Name:  "TENANT_ADMIN_RW",
		Scope: model.RoleScopeSystemTenant,
		Permissions: []model.Permission{
			{Name: "user.assign_role"},
			{Name: "role.assign"},
		},
	}
	roleRepo.roles[adminRoleID] = adminRole

	memberRoleID := uuid.New()
	memberRole := &model.Role{
		ID:    memberRoleID,
		Name:  "TENANT_USER",
		Scope: model.RoleScopeSystemTenant,
	}
	roleRepo.roles[memberRoleID] = memberRole

	adminUserID := uuid.New()
	userRepo.users[adminUserID] = &model.User{ID: adminUserID, Status: "active"}
	userRepo.CreateWithTenantRole(context.Background(), userRepo.users[adminUserID], tenantID, adminRoleID)
	roleAssignRepo.AssignTenantRole(context.Background(), adminUserID, tenantID, adminRoleID)

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignRepo, authzRepo, sessionRepo)
	if err != nil {
		t.Fatalf("failed to create tenant user service: %v", err)
	}

	// Attempting to demote the single admin to member role should fail with ErrCannotRemoveLastAdmin
	_, err = svc.ChangeTenantUserRole(context.Background(), tenantID, adminUserID, memberRoleID)
	if !errors.Is(err, service.ErrCannotRemoveLastAdmin) {
		t.Fatalf("expected ErrCannotRemoveLastAdmin on demote, got %v", err)
	}

	// Attempting to remove the single admin should fail with ErrCannotRemoveLastAdmin
	err = svc.RemoveTenantMember(context.Background(), tenantID, adminUserID)
	if !errors.Is(err, service.ErrCannotRemoveLastAdmin) {
		t.Fatalf("expected ErrCannotRemoveLastAdmin on remove, got %v", err)
	}
}

func TestTenantUserService_DeactivateUser_RevokesSessions(t *testing.T) {
	userRepo := newMockUserRepoForUserService()
	tenantRepo := newMockTenantRepoForUserService()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignRepo()
	authzRepo := newMockAuthorizationRepository()
	sessionRepo := &mockSessionRepoForUserService{revokedUsers: make(map[uuid.UUID]bool)}

	targetUserID := uuid.New()
	userRepo.users[targetUserID] = &model.User{ID: targetUserID, Status: "active"}

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignRepo, authzRepo, sessionRepo)
	if err != nil {
		t.Fatalf("failed to create tenant user service: %v", err)
	}

	err = svc.DeactivateUser(context.Background(), targetUserID)
	if err != nil {
		t.Fatalf("unexpected error deactivating user: %v", err)
	}

	if userRepo.users[targetUserID].Status != "deactivated" {
		t.Fatalf("expected user status deactivated, got %s", userRepo.users[targetUserID].Status)
	}

	if !sessionRepo.revokedUsers[targetUserID] {
		t.Fatalf("expected sessions to be revoked for deactivated user")
	}
}
