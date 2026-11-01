package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
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
	for _, u := range m.users {
		if u.Email == user.Email {
			return repository.ErrDuplicateEmail
		}
	}
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
	tenantRoles, ok := m.members[tenantID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	roleID, ok := tenantRoles[userID]
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
	userRepo      *mockUserRepoForUserService
	assignments   map[uuid.UUID]map[uuid.UUID]uuid.UUID // tenantID -> userID -> roleID
	platformRoles map[uuid.UUID]*model.Role
}

func newMockRoleAssignRepo() *mockRoleAssignRepo {
	return &mockRoleAssignRepo{
		assignments:   make(map[uuid.UUID]map[uuid.UUID]uuid.UUID),
		platformRoles: make(map[uuid.UUID]*model.Role),
	}
}

func (m *mockRoleAssignRepo) AssignTenantRole(ctx context.Context, userID, tenantID, roleID uuid.UUID) error {
	if m.assignments[tenantID] == nil {
		m.assignments[tenantID] = make(map[uuid.UUID]uuid.UUID)
	}
	m.assignments[tenantID][userID] = roleID
	if m.userRepo != nil {
		if m.userRepo.members[tenantID] == nil {
			m.userRepo.members[tenantID] = make(map[uuid.UUID]uuid.UUID)
		}
		m.userRepo.members[tenantID][userID] = roleID
	}
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
func (m *mockRoleAssignRepo) GetPlatformRole(ctx context.Context, userID uuid.UUID) (*model.Role, error) {
	r, ok := m.platformRoles[userID]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return r, nil
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
	authzService, _ := service.NewAuthorizationService(authzRepo)

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

	tokenID := uuid.New()
	adminPrincipal := &identity.Principal{
		UserID:    adminUserID,
		SessionID: uuid.New(),
		TokenID:   tokenID,
	}

	authzRepo.setActiveTenantAdmins(tenantID, 1)
	authzRepo.setTenantRole(adminUserID, tenantID, adminRole)
	authzRepo.grantTenant(adminUserID, tenantID, "user.assign_role")
	authzRepo.grantTenant(adminUserID, tenantID, "role.assign")
	authzRepo.grantTenant(adminUserID, tenantID, "user.remove")

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignRepo, authzRepo, sessionRepo, authzService)
	if err != nil {
		t.Fatalf("failed to create tenant user service: %v", err)
	}

	// Attempting to demote the single admin to member role should fail with ErrCannotRemoveLastAdmin
	_, err = svc.ChangeTenantUserRole(context.Background(), adminPrincipal, tenantID, adminUserID, memberRoleID)
	if !errors.Is(err, service.ErrCannotRemoveLastAdmin) {
		t.Fatalf("expected ErrCannotRemoveLastAdmin on demote, got %v", err)
	}

	// Attempting to remove the single admin should fail with ErrCannotRemoveLastAdmin
	err = svc.RemoveTenantMember(context.Background(), adminPrincipal, tenantID, adminUserID)
	if !errors.Is(err, service.ErrCannotRemoveLastAdmin) {
		t.Fatalf("expected ErrCannotRemoveLastAdmin on remove, got %v", err)
	}
}

func TestTenantUserService_Delegation_TenantAdminCannotGrantPermissionsTheyLack(t *testing.T) {
	userRepo := newMockUserRepoForUserService()
	tenantRepo := newMockTenantRepoForUserService()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignRepo()
	authzRepo := newMockAuthorizationRepository()
	sessionRepo := &mockSessionRepoForUserService{revokedUsers: make(map[uuid.UUID]bool)}
	authzService, _ := service.NewAuthorizationService(authzRepo)

	tenantID := uuid.New()
	tenantRepo.tenants[tenantID] = &model.Tenant{ID: tenantID, Status: "active"}

	// Actor only has user.read and user.create
	actorRoleID := uuid.New()
	actorRole := &model.Role{
		ID:       actorRoleID,
		Name:     "LIMITED_ADMIN",
		Scope:    model.RoleScopeCustomTenant,
		TenantID: &tenantID,
		Permissions: []model.Permission{
			{Name: "user.read"},
			{Name: "user.create"},
			{Name: "user.assign_role"},
		},
	}
	roleRepo.roles[actorRoleID] = actorRole

	// Target role has workflow.execute, which actor lacks
	targetRoleID := uuid.New()
	targetRole := &model.Role{
		ID:       targetRoleID,
		Name:     "WORKFLOW_MASTER",
		Scope:    model.RoleScopeCustomTenant,
		TenantID: &tenantID,
		Permissions: []model.Permission{
			{Name: "user.read"},
			{Name: "workflow.execute"},
		},
	}
	roleRepo.roles[targetRoleID] = targetRole

	actorID := uuid.New()
	tokenID := uuid.New()
	actorPrincipal := &identity.Principal{
		UserID:    actorID,
		SessionID: uuid.New(),
		TokenID:   tokenID,
	}

	authzRepo.setTenantRole(actorID, tenantID, actorRole)
	authzRepo.grantTenant(actorID, tenantID, "user.assign_role")

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignRepo, authzRepo, sessionRepo, authzService)
	if err != nil {
		t.Fatalf("failed to create tenant user service: %v", err)
	}

	// Provisioning with a role containing permissions actor lacks must fail with ErrCannotDelegateRole
	_, err = svc.ProvisionTenantUser(context.Background(), actorPrincipal, tenantID, "newuser@example.com", "Password123!", targetRoleID)
	if !errors.Is(err, service.ErrCannotDelegateRole) {
		t.Fatalf("expected ErrCannotDelegateRole, got %v", err)
	}
}

func TestTenantUserService_AddTenantMember_PlatformAdminAllowed_TenantAdminForbidden(t *testing.T) {
	userRepo := newMockUserRepoForUserService()
	tenantRepo := newMockTenantRepoForUserService()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignRepo()
	roleAssignRepo.userRepo = userRepo
	authzRepo := newMockAuthorizationRepository()
	sessionRepo := &mockSessionRepoForUserService{revokedUsers: make(map[uuid.UUID]bool)}
	authzService, _ := service.NewAuthorizationService(authzRepo)

	tenantID := uuid.New()
	tenantRepo.tenants[tenantID] = &model.Tenant{ID: tenantID, Status: "active"}

	targetUserID := uuid.New()
	userRepo.users[targetUserID] = &model.User{ID: targetUserID, Email: "existing@example.com", Status: "active"}

	roleID := uuid.New()
	roleRepo.roles[roleID] = &model.Role{
		ID:    roleID,
		Name:  "TENANT_USER",
		Scope: model.RoleScopeSystemTenant,
	}

	// 1. Tenant Admin attempting to directly add existing global user must be forbidden
	tenantAdminID := uuid.New()
	token1 := uuid.New()
	tenantAdminPrincipal := &identity.Principal{
		UserID:    tenantAdminID,
		SessionID: uuid.New(),
		TokenID:   token1,
	}
	// Tenant admin does NOT have platform role.assign

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignRepo, authzRepo, sessionRepo, authzService)
	if err != nil {
		t.Fatalf("failed to create tenant user service: %v", err)
	}

	_, err = svc.AddTenantMember(context.Background(), tenantAdminPrincipal, tenantID, targetUserID, roleID)
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for tenant admin adding existing global user, got %v", err)
	}

	// 2. Platform Admin with platform role.assign is permitted
	platformAdminID := uuid.New()
	token2 := uuid.New()
	platformAdminPrincipal := &identity.Principal{
		UserID:    platformAdminID,
		SessionID: uuid.New(),
		TokenID:   token2,
	}
	authzRepo.grantPlatform(platformAdminID, "role.assign")

	member, err := svc.AddTenantMember(context.Background(), platformAdminPrincipal, tenantID, targetUserID, roleID)
	if err != nil {
		t.Fatalf("unexpected error for platform admin adding member: %v", err)
	}
	if member.UserID != targetUserID {
		t.Fatalf("expected member user ID %s, got %s", targetUserID, member.UserID)
	}
}

func TestTenantUserService_ProvisionTenantUser_DuplicateEmailConflict(t *testing.T) {
	userRepo := newMockUserRepoForUserService()
	tenantRepo := newMockTenantRepoForUserService()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignRepo()
	authzRepo := newMockAuthorizationRepository()
	sessionRepo := &mockSessionRepoForUserService{revokedUsers: make(map[uuid.UUID]bool)}
	authzService, _ := service.NewAuthorizationService(authzRepo)

	tenantID := uuid.New()
	tenantRepo.tenants[tenantID] = &model.Tenant{ID: tenantID, Status: "active"}

	roleID := uuid.New()
	roleRepo.roles[roleID] = &model.Role{
		ID:    roleID,
		Name:  "TENANT_USER",
		Scope: model.RoleScopeSystemTenant,
	}

	// Pre-existing user with same email
	existingID := uuid.New()
	userRepo.users[existingID] = &model.User{
		ID:     existingID,
		Email:  "duplicate@example.com",
		Status: "active",
	}

	adminID := uuid.New()
	tokenID := uuid.New()
	adminPrincipal := &identity.Principal{
		UserID:    adminID,
		SessionID: uuid.New(),
		TokenID:   tokenID,
	}
	authzRepo.grantPlatform(adminID, "role.assign")

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignRepo, authzRepo, sessionRepo, authzService)
	if err != nil {
		t.Fatalf("failed to create tenant user service: %v", err)
	}

	_, err = svc.ProvisionTenantUser(context.Background(), adminPrincipal, tenantID, "duplicate@example.com", "Password123!", roleID)
	if !errors.Is(err, service.ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists on duplicate email, got %v", err)
	}
}

func TestTenantUserService_DeactivateUser_RevokesSessions(t *testing.T) {
	userRepo := newMockUserRepoForUserService()
	tenantRepo := newMockTenantRepoForUserService()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignRepo()
	authzRepo := newMockAuthorizationRepository()
	sessionRepo := &mockSessionRepoForUserService{revokedUsers: make(map[uuid.UUID]bool)}
	authzService, _ := service.NewAuthorizationService(authzRepo)

	targetUserID := uuid.New()
	userRepo.users[targetUserID] = &model.User{ID: targetUserID, Status: "active"}

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignRepo, authzRepo, sessionRepo, authzService)
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
