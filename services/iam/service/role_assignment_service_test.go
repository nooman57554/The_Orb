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

type mockRoleAssignmentRepo struct {
	assignTenantRole      func(ctx context.Context, userID, tenantID, roleID uuid.UUID) error
	removeTenantRole      func(ctx context.Context, userID, tenantID uuid.UUID) error
	listUsersByTenantRole func(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error)
	assignPlatformRole    func(ctx context.Context, userID, roleID uuid.UUID) error
	removePlatformRole    func(ctx context.Context, userID uuid.UUID) error
	getPlatformRole       func(ctx context.Context, userID uuid.UUID) (*model.Role, error)
	countPlatformAdmins   func(ctx context.Context) (int, error)
}

func (m *mockRoleAssignmentRepo) AssignTenantRole(ctx context.Context, userID, tenantID, roleID uuid.UUID) error {
	if m.assignTenantRole != nil {
		return m.assignTenantRole(ctx, userID, tenantID, roleID)
	}
	return nil
}

func (m *mockRoleAssignmentRepo) RemoveTenantRole(ctx context.Context, userID, tenantID uuid.UUID) error {
	if m.removeTenantRole != nil {
		return m.removeTenantRole(ctx, userID, tenantID)
	}
	return nil
}

func (m *mockRoleAssignmentRepo) ListUsersByTenantRole(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error) {
	if m.listUsersByTenantRole != nil {
		return m.listUsersByTenantRole(ctx, tenantID, roleID)
	}
	return nil, nil
}

func (m *mockRoleAssignmentRepo) AssignPlatformRole(ctx context.Context, userID, roleID uuid.UUID) error {
	if m.assignPlatformRole != nil {
		return m.assignPlatformRole(ctx, userID, roleID)
	}
	return nil
}

func (m *mockRoleAssignmentRepo) RemovePlatformRole(ctx context.Context, userID uuid.UUID) error {
	if m.removePlatformRole != nil {
		return m.removePlatformRole(ctx, userID)
	}
	return nil
}

func (m *mockRoleAssignmentRepo) GetPlatformRole(ctx context.Context, userID uuid.UUID) (*model.Role, error) {
	if m.getPlatformRole != nil {
		return m.getPlatformRole(ctx, userID)
	}
	return nil, repository.ErrNotFound
}

func (m *mockRoleAssignmentRepo) CountPlatformAdmins(ctx context.Context) (int, error) {
	if m.countPlatformAdmins != nil {
		return m.countPlatformAdmins(ctx)
	}
	return 1, nil
}

type mockUserRepoForRoleAssign struct {
	users map[uuid.UUID]*model.User
}

func (m *mockUserRepoForRoleAssign) Create(ctx context.Context, user *model.User) error { return nil }
func (m *mockUserRepoForRoleAssign) CreateWithTenantRole(ctx context.Context, user *model.User, tenantID, roleID uuid.UUID) error {
	return nil
}
func (m *mockUserRepoForRoleAssign) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	if m.users != nil {
		if u, ok := m.users[id]; ok {
			return u, nil
		}
	}
	return nil, repository.ErrNotFound
}
func (m *mockUserRepoForRoleAssign) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	return nil, nil
}
func (m *mockUserRepoForRoleAssign) GetByIDInTenant(ctx context.Context, userID, tenantID uuid.UUID) (*model.TenantMemberRecord, error) {
	return nil, nil
}
func (m *mockUserRepoForRoleAssign) ListByTenant(ctx context.Context, tenantID uuid.UUID, offset, limit int) ([]model.TenantMemberRecord, int, error) {
	return nil, 0, nil
}
func (m *mockUserRepoForRoleAssign) Update(ctx context.Context, user *model.User) error { return nil }
func (m *mockUserRepoForRoleAssign) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

type mockTenantRepoForRoleAssign struct {
	tenants map[uuid.UUID]*model.Tenant
}

func (m *mockTenantRepoForRoleAssign) Create(ctx context.Context, tenant *model.Tenant) error {
	return nil
}
func (m *mockTenantRepoForRoleAssign) GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	if m.tenants != nil {
		if t, ok := m.tenants[id]; ok {
			return t, nil
		}
	}
	return nil, repository.ErrNotFound
}
func (m *mockTenantRepoForRoleAssign) GetBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	return nil, nil
}
func (m *mockTenantRepoForRoleAssign) List(ctx context.Context, offset, limit int) ([]model.Tenant, int, error) {
	return nil, 0, nil
}
func (m *mockTenantRepoForRoleAssign) Update(ctx context.Context, tenant *model.Tenant) error {
	return nil
}
func (m *mockTenantRepoForRoleAssign) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func TestNewRoleAssignmentService_ConstructorValidation(t *testing.T) {
	roleAssignRepo := &mockRoleAssignmentRepo{}
	roleRepo := &mockRoleRepository{}
	userRepo := &mockUserRepoForRoleAssign{}
	tenantRepo := &mockTenantRepoForRoleAssign{}
	authzRepo := newMockAuthorizationRepository()
	authzSvc, _ := service.NewAuthorizationService(authzRepo)

	t.Run("nil dependencies fail with error", func(t *testing.T) {
		if _, err := service.NewRoleAssignmentService(nil, roleRepo, userRepo, tenantRepo, authzRepo, authzSvc); err == nil {
			t.Fatal("expected error on nil roleAssignRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, nil, userRepo, tenantRepo, authzRepo, authzSvc); err == nil {
			t.Fatal("expected error on nil roleRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, nil, tenantRepo, authzRepo, authzSvc); err == nil {
			t.Fatal("expected error on nil userRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, nil, authzRepo, authzSvc); err == nil {
			t.Fatal("expected error on nil tenantRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, nil, authzSvc); err == nil {
			t.Fatal("expected error on nil authzRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo, nil); err == nil {
			t.Fatal("expected error on nil authzService")
		}
	})

	t.Run("all dependencies present succeeds", func(t *testing.T) {
		svc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo, authzSvc)
		if err != nil || svc == nil {
			t.Fatalf("expected successful construction, got err: %v", err)
		}
	})
}

func TestRoleAssignmentService_PlatformScope(t *testing.T) {
	ctx := context.Background()
	adminActorID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	targetUserID := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	platformRoleID := uuid.MustParse("018f0000-0000-7000-8000-000000000003")
	sessionID := uuid.MustParse("018f0000-0000-7000-8000-000000000004")

	adminPrincipal := &identity.Principal{
		UserID:    adminActorID,
		SessionID: sessionID,
		TokenID:   uuid.New(),
	}

	setupFixtures := func() (
		*mockRoleAssignmentRepo,
		*mockRoleRepository,
		*mockUserRepoForRoleAssign,
		*mockTenantRepoForRoleAssign,
		*mockAuthorizationRepository,
		*service.RoleAssignmentService,
	) {
		assignRepo := &mockRoleAssignmentRepo{}
		roleRepo := &mockRoleRepository{}
		userRepo := &mockUserRepoForRoleAssign{users: make(map[uuid.UUID]*model.User)}
		tenantRepo := &mockTenantRepoForRoleAssign{tenants: make(map[uuid.UUID]*model.Tenant)}
		authzRepo := newMockAuthorizationRepository()
		authzSvc, _ := service.NewAuthorizationService(authzRepo)
		svc, _ := service.NewRoleAssignmentService(assignRepo, roleRepo, userRepo, tenantRepo, authzRepo, authzSvc)
		return assignRepo, roleRepo, userRepo, tenantRepo, authzRepo, svc
	}

	t.Run("self modification rejected", func(t *testing.T) {
		_, _, _, _, _, svc := setupFixtures()
		err := svc.AssignRole(ctx, adminPrincipal, service.AssignRoleRequest{
			Scope:  service.AssignmentScopePlatform,
			UserID: adminActorID,
			RoleID: platformRoleID,
		})
		if !errors.Is(err, service.ErrCannotModifyOwnPlatformRole) {
			t.Fatalf("expected ErrCannotModifyOwnPlatformRole, got: %v", err)
		}

		err = svc.RemoveRole(ctx, adminPrincipal, service.RemoveRoleRequest{
			Scope:  service.AssignmentScopePlatform,
			UserID: adminActorID,
		})
		if !errors.Is(err, service.ErrCannotModifyOwnPlatformRole) {
			t.Fatalf("expected ErrCannotModifyOwnPlatformRole on remove, got: %v", err)
		}
	})

	t.Run("actor without platform role.assign rejected with ErrForbidden", func(t *testing.T) {
		_, _, _, _, _, svc := setupFixtures()
		nonAdmin := &identity.Principal{
			UserID:    uuid.New(),
			SessionID: sessionID,
			TokenID:   uuid.New(),
		}
		err := svc.AssignRole(ctx, nonAdmin, service.AssignRoleRequest{
			Scope:  service.AssignmentScopePlatform,
			UserID: targetUserID,
			RoleID: platformRoleID,
		})
		if !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("expected ErrForbidden, got: %v", err)
		}
	})

	t.Run("inactive target user rejected", func(t *testing.T) {
		_, roleRepo, userRepo, _, authzRepo, svc := setupFixtures()
		authzRepo.grantPlatform(adminActorID, "role.assign")

		roleRepo.roles = map[uuid.UUID]*model.Role{
			platformRoleID: {ID: platformRoleID, Name: "VIEWER", Scope: model.RoleScopePlatform},
		}
		userRepo.users = map[uuid.UUID]*model.User{
			targetUserID: {ID: targetUserID, Status: "deactivated"},
		}

		err := svc.AssignRole(ctx, adminPrincipal, service.AssignRoleRequest{
			Scope:  service.AssignmentScopePlatform,
			UserID: targetUserID,
			RoleID: platformRoleID,
		})
		if !errors.Is(err, service.ErrInactiveUser) {
			t.Fatalf("expected ErrInactiveUser, got: %v", err)
		}
	})

	t.Run("demote last active platform admin rejected", func(t *testing.T) {
		assignRepo, roleRepo, userRepo, _, authzRepo, svc := setupFixtures()
		authzRepo.grantPlatform(adminActorID, "role.assign")

		roleRepo.roles = map[uuid.UUID]*model.Role{
			platformRoleID: {ID: platformRoleID, Name: "AUDITOR", Scope: model.RoleScopePlatform},
		}
		userRepo.users = map[uuid.UUID]*model.User{
			targetUserID: {ID: targetUserID, Status: "active"},
		}
		assignRepo.getPlatformRole = func(ctx context.Context, userID uuid.UUID) (*model.Role, error) {
			return &model.Role{Name: "PLATFORM_ADMIN", Scope: model.RoleScopePlatform}, nil
		}
		assignRepo.countPlatformAdmins = func(ctx context.Context) (int, error) {
			return 1, nil
		}

		err := svc.AssignRole(ctx, adminPrincipal, service.AssignRoleRequest{
			Scope:  service.AssignmentScopePlatform,
			UserID: targetUserID,
			RoleID: platformRoleID,
		})
		if !errors.Is(err, service.ErrCannotRemoveLastPlatformAdmin) {
			t.Fatalf("expected ErrCannotRemoveLastPlatformAdmin, got: %v", err)
		}
	})

	t.Run("successful platform role assignment", func(t *testing.T) {
		assignRepo, roleRepo, userRepo, _, authzRepo, svc := setupFixtures()
		authzRepo.grantPlatform(adminActorID, "role.assign")

		roleRepo.roles = map[uuid.UUID]*model.Role{
			platformRoleID: {ID: platformRoleID, Name: "PLATFORM_ADMIN", Scope: model.RoleScopePlatform},
		}
		userRepo.users = map[uuid.UUID]*model.User{
			targetUserID: {ID: targetUserID, Status: "active"},
		}

		assigned := false
		assignRepo.assignPlatformRole = func(ctx context.Context, uID, rID uuid.UUID) error {
			assigned = true
			return nil
		}

		err := svc.AssignRole(ctx, adminPrincipal, service.AssignRoleRequest{
			Scope:  service.AssignmentScopePlatform,
			UserID: targetUserID,
			RoleID: platformRoleID,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !assigned {
			t.Fatal("expected assignPlatformRole to be called")
		}
	})
}

func TestRoleAssignmentService_TenantScope(t *testing.T) {
	ctx := context.Background()
	adminActorID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	targetUserID := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	tenantID := uuid.MustParse("018f0000-0000-7000-8000-000000000003")
	tenantRoleID := uuid.MustParse("018f0000-0000-7000-8000-000000000004")
	sessionID := uuid.MustParse("018f0000-0000-7000-8000-000000000005")

	actorPrincipal := &identity.Principal{
		UserID:    adminActorID,
		SessionID: sessionID,
		TokenID:   uuid.New(),
	}

	setupFixtures := func() (
		*mockRoleAssignmentRepo,
		*mockRoleRepository,
		*mockUserRepoForRoleAssign,
		*mockTenantRepoForRoleAssign,
		*mockAuthorizationRepository,
		*service.RoleAssignmentService,
	) {
		assignRepo := &mockRoleAssignmentRepo{}
		roleRepo := &mockRoleRepository{}
		userRepo := &mockUserRepoForRoleAssign{users: make(map[uuid.UUID]*model.User)}
		tenantRepo := &mockTenantRepoForRoleAssign{tenants: make(map[uuid.UUID]*model.Tenant)}
		authzRepo := newMockAuthorizationRepository()
		authzSvc, _ := service.NewAuthorizationService(authzRepo)
		svc, _ := service.NewRoleAssignmentService(assignRepo, roleRepo, userRepo, tenantRepo, authzRepo, authzSvc)
		return assignRepo, roleRepo, userRepo, tenantRepo, authzRepo, svc
	}

	t.Run("inactive tenant rejected with ErrInactiveTenant", func(t *testing.T) {
		_, _, _, tenantRepo, _, svc := setupFixtures()
		tenantRepo.tenants = map[uuid.UUID]*model.Tenant{
			tenantID: {ID: tenantID, Status: "deactivated"},
		}

		err := svc.AssignRole(ctx, actorPrincipal, service.AssignRoleRequest{
			Scope:    service.AssignmentScopeTenant,
			UserID:   targetUserID,
			RoleID:   tenantRoleID,
			TenantID: tenantID,
		})
		if !errors.Is(err, service.ErrInactiveTenant) {
			t.Fatalf("expected ErrInactiveTenant, got: %v", err)
		}
	})

	t.Run("custom tenant role owned by another tenant rejected with ErrRoleNotFound", func(t *testing.T) {
		otherTenantID := uuid.New()
		_, roleRepo, userRepo, tenantRepo, _, svc := setupFixtures()
		tenantRepo.tenants = map[uuid.UUID]*model.Tenant{
			tenantID: {ID: tenantID, Status: "active"},
		}
		userRepo.users = map[uuid.UUID]*model.User{
			targetUserID: {ID: targetUserID, Status: "active"},
		}
		roleRepo.roles = map[uuid.UUID]*model.Role{
			tenantRoleID: {
				ID:       tenantRoleID,
				Scope:    model.RoleScopeCustomTenant,
				TenantID: &otherTenantID,
			},
		}

		err := svc.AssignRole(ctx, actorPrincipal, service.AssignRoleRequest{
			Scope:    service.AssignmentScopeTenant,
			UserID:   targetUserID,
			RoleID:   tenantRoleID,
			TenantID: tenantID,
		})
		if !errors.Is(err, service.ErrRoleNotFound) {
			t.Fatalf("expected ErrRoleNotFound, got: %v", err)
		}
	})

	t.Run("delegation authority check rejects unauthorized permissions", func(t *testing.T) {
		_, roleRepo, userRepo, tenantRepo, authzRepo, svc := setupFixtures()
		tenantRepo.tenants = map[uuid.UUID]*model.Tenant{
			tenantID: {ID: tenantID, Status: "active"},
		}
		userRepo.users = map[uuid.UUID]*model.User{
			targetUserID: {ID: targetUserID, Status: "active"},
		}
		roleRepo.roles = map[uuid.UUID]*model.Role{
			tenantRoleID: {
				ID:    tenantRoleID,
				Scope: model.RoleScopeSystemTenant,
				Permissions: []model.Permission{
					{Name: "user.read"},
					{Name: "secret.admin"}, // actor does NOT have this
				},
			},
		}

		// Actor has tenant permission user.assign_role, but actor's role only has user.read
		authzRepo.grantTenant(adminActorID, tenantID, "user.assign_role")
		actorRoleID := uuid.New()
		authzRepo.setTenantRole(adminActorID, tenantID, &model.Role{
			ID:    actorRoleID,
			Name:  "TENANT_MEMBER",
			Scope: model.RoleScopeSystemTenant,
			Permissions: []model.Permission{
				{Name: "user.read"},
				{Name: "user.assign_role"},
			},
		})

		err := svc.AssignRole(ctx, actorPrincipal, service.AssignRoleRequest{
			Scope:    service.AssignmentScopeTenant,
			UserID:   targetUserID,
			RoleID:   tenantRoleID,
			TenantID: tenantID,
		})
		if !errors.Is(err, service.ErrCannotDelegateRole) {
			t.Fatalf("expected ErrCannotDelegateRole, got: %v", err)
		}
	})

	t.Run("successful tenant role assignment", func(t *testing.T) {
		assignRepo, roleRepo, userRepo, tenantRepo, authzRepo, svc := setupFixtures()
		tenantRepo.tenants = map[uuid.UUID]*model.Tenant{
			tenantID: {ID: tenantID, Status: "active"},
		}
		userRepo.users = map[uuid.UUID]*model.User{
			targetUserID: {ID: targetUserID, Status: "active"},
		}
		roleRepo.roles = map[uuid.UUID]*model.Role{
			tenantRoleID: {
				ID:    tenantRoleID,
				Scope: model.RoleScopeSystemTenant,
				Permissions: []model.Permission{
					{Name: "user.read"},
				},
			},
		}

		authzRepo.grantTenant(adminActorID, tenantID, "user.assign_role")
		authzRepo.setTenantRole(adminActorID, tenantID, &model.Role{
			ID:    uuid.New(),
			Name:  "TENANT_ADMIN_RW",
			Scope: model.RoleScopeSystemTenant,
			Permissions: []model.Permission{
				{Name: "user.read"},
				{Name: "user.assign_role"},
			},
		})

		assigned := false
		assignRepo.assignTenantRole = func(ctx context.Context, uID, tID, rID uuid.UUID) error {
			assigned = true
			return nil
		}

		err := svc.AssignRole(ctx, actorPrincipal, service.AssignRoleRequest{
			Scope:    service.AssignmentScopeTenant,
			UserID:   targetUserID,
			RoleID:   tenantRoleID,
			TenantID: tenantID,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !assigned {
			t.Fatal("expected assignTenantRole to be called")
		}
	})

	t.Run("demote last tenant admin rejected", func(t *testing.T) {
		_, roleRepo, userRepo, tenantRepo, authzRepo, svc := setupFixtures()
		tenantRepo.tenants = map[uuid.UUID]*model.Tenant{
			tenantID: {ID: tenantID, Status: "active"},
		}
		userRepo.users = map[uuid.UUID]*model.User{
			targetUserID: {ID: targetUserID, Status: "active"},
		}
		memberRoleID := uuid.New()
		roleRepo.roles = map[uuid.UUID]*model.Role{
			memberRoleID: {
				ID:          memberRoleID,
				Name:        "TENANT_MEMBER",
				Scope:       model.RoleScopeSystemTenant,
				Permissions: []model.Permission{{Name: "user.read"}},
			},
		}

		// Platform admin actor
		authzRepo.grantPlatform(adminActorID, "role.assign")

		// Target user is currently tenant admin
		currentAdminRoleID := uuid.New()
		authzRepo.setTenantRole(targetUserID, tenantID, &model.Role{
			ID:          currentAdminRoleID,
			Name:        "TENANT_ADMIN_RW",
			Scope:       model.RoleScopeSystemTenant,
			Permissions: []model.Permission{{Name: "user.assign_role"}},
		})
		authzRepo.setActiveTenantAdmins(tenantID, 1)

		err := svc.AssignRole(ctx, actorPrincipal, service.AssignRoleRequest{
			Scope:    service.AssignmentScopeTenant,
			UserID:   targetUserID,
			RoleID:   memberRoleID,
			TenantID: tenantID,
		})
		if !errors.Is(err, service.ErrCannotRemoveLastAdmin) {
			t.Fatalf("expected ErrCannotRemoveLastAdmin, got: %v", err)
		}
	})
}

func TestRoleAssignmentService_ReadOperations(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()
	roleID := uuid.New()

	assignRepo := &mockRoleAssignmentRepo{}
	roleRepo := &mockRoleRepository{}
	userRepo := &mockUserRepoForRoleAssign{users: make(map[uuid.UUID]*model.User)}
	tenantRepo := &mockTenantRepoForRoleAssign{tenants: make(map[uuid.UUID]*model.Tenant)}
	authzRepo := newMockAuthorizationRepository()
	authzSvc, _ := service.NewAuthorizationService(authzRepo)
	svc, _ := service.NewRoleAssignmentService(assignRepo, roleRepo, userRepo, tenantRepo, authzRepo, authzSvc)

	t.Run("GetPlatformRole success and not found", func(t *testing.T) {
		assignRepo.getPlatformRole = func(ctx context.Context, u uuid.UUID) (*model.Role, error) {
			if u == userID {
				return &model.Role{ID: roleID, Name: "AUDITOR"}, nil
			}
			return nil, repository.ErrNotFound
		}

		r, err := svc.GetPlatformRole(ctx, userID)
		if err != nil || r == nil || r.Name != "AUDITOR" {
			t.Fatalf("expected AUDITOR role, got %v, err: %v", r, err)
		}

		_, err = svc.GetPlatformRole(ctx, uuid.New())
		if !errors.Is(err, service.ErrRoleNotFound) {
			t.Fatalf("expected ErrRoleNotFound, got %v", err)
		}
	})

	t.Run("GetTenantRole success and not found", func(t *testing.T) {
		authzRepo.setTenantRole(userID, tenantID, &model.Role{ID: roleID, Name: "TENANT_MEMBER"})

		r, err := svc.GetTenantRole(ctx, userID, tenantID)
		if err != nil || r == nil || r.Name != "TENANT_MEMBER" {
			t.Fatalf("expected TENANT_MEMBER role, got %v, err: %v", r, err)
		}

		_, err = svc.GetTenantRole(ctx, uuid.New(), tenantID)
		if !errors.Is(err, service.ErrMemberNotFound) {
			t.Fatalf("expected ErrMemberNotFound, got %v", err)
		}
	})

	t.Run("ListUsersByRole delegates to repo", func(t *testing.T) {
		assignRepo.listUsersByTenantRole = func(ctx context.Context, tID, rID uuid.UUID) ([]model.TenantMemberRecord, error) {
			return []model.TenantMemberRecord{
				{UserID: userID, Email: "user@example.com", JoinedAt: time.Now()},
			}, nil
		}

		members, err := svc.ListUsersByRole(ctx, tenantID, roleID)
		if err != nil || len(members) != 1 || members[0].Email != "user@example.com" {
			t.Fatalf("expected 1 member record, got %v, err: %v", members, err)
		}
	})
}
