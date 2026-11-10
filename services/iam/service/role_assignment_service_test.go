package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

func TestNewRoleAssignmentService_ConstructorValidation(t *testing.T) {
	roleAssignRepo := newMockRoleAssignmentRepo()
	roleRepo := newMockRoleRepository()
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()
	authzRepo := newMockAuthorizationRepository()

	t.Run("nil dependencies fail with error", func(t *testing.T) {
		if _, err := service.NewRoleAssignmentService(nil, roleRepo, userRepo, tenantRepo, authzRepo); err == nil {
			t.Fatal("expected error on nil roleAssignRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, nil, userRepo, tenantRepo, authzRepo); err == nil {
			t.Fatal("expected error on nil roleRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, nil, tenantRepo, authzRepo); err == nil {
			t.Fatal("expected error on nil userRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, nil, authzRepo); err == nil {
			t.Fatal("expected error on nil tenantRepo")
		}
		if _, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, nil); err == nil {
			t.Fatal("expected error on nil authzRepo")
		}
	})

	t.Run("all dependencies present succeeds", func(t *testing.T) {
		svc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
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
		*mockUserRepository,
		*mockTenantRepository,
		*mockAuthorizationRepository,
		*service.RoleAssignmentService,
	) {
		assignRepo := newMockRoleAssignmentRepo()
		roleRepo := newMockRoleRepository()
		userRepo := newMockUserRepository()
		tenantRepo := newMockTenantRepository()
		authzRepo := newMockAuthorizationRepository()
		svc, _ := service.NewRoleAssignmentService(assignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
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
		authzRepo.grantPlatform(adminActorID, authorization.PermPlatformRoleAssign)

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
		authzRepo.grantPlatform(adminActorID, authorization.PermPlatformRoleAssign)

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
		authzRepo.grantPlatform(adminActorID, authorization.PermPlatformRoleAssign)

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

func TestRoleAssignmentService_PlatformAdminMembership_Section19(t *testing.T) {
	ctx := context.Background()
	adminA := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	adminB := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	ordinaryUser := uuid.MustParse("018f0000-0000-7000-8000-000000000003")
	tenantX := uuid.MustParse("018f0000-0000-7000-8000-000000000010")
	tenantY := uuid.MustParse("018f0000-0000-7000-8000-000000000020")
	tenantRoleID := uuid.MustParse("018f0000-0000-7000-8000-000000000030")

	principalAdminA := &identity.Principal{
		UserID:    adminA,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	setup := func() (
		*mockRoleAssignmentRepo,
		*mockRoleRepository,
		*mockUserRepository,
		*mockTenantRepository,
		*mockAuthorizationRepository,
		*service.RoleAssignmentService,
	) {
		assignRepo := newMockRoleAssignmentRepo()
		roleRepo := newMockRoleRepository()
		userRepo := newMockUserRepository()
		tenantRepo := newMockTenantRepository()
		authzRepo := newMockAuthorizationRepository()

		// Register platform admins and users
		userRepo.users[adminA] = &model.User{ID: adminA, Status: "active"}
		userRepo.users[adminB] = &model.User{ID: adminB, Status: "active"}
		userRepo.users[ordinaryUser] = &model.User{ID: ordinaryUser, Status: "active"}

		// Register tenants
		tenantRepo.tenants[tenantX] = &model.Tenant{ID: tenantX, Status: "active"}
		tenantRepo.tenants[tenantY] = &model.Tenant{ID: tenantY, Status: "active"}

		// Register platform role for Admin A
		platAdminRoleID := uuid.New()
		roleRepo.roles[platAdminRoleID] = &model.Role{ID: platAdminRoleID, Name: "PLATFORM_ADMIN", Scope: model.RoleScopePlatform}
		assignRepo.platformAssignments[adminA] = platAdminRoleID
		assignRepo.roles[platAdminRoleID] = roleRepo.roles[platAdminRoleID]
		authzRepo.grantPlatform(adminA, authorization.PermPlatformRoleAssign)

		// Register system tenant role
		roleRepo.roles[tenantRoleID] = &model.Role{
			ID:    tenantRoleID,
			Name:  "TENANT_USER",
			Scope: model.RoleScopeSystemTenant,
		}

		svc, _ := service.NewRoleAssignmentService(assignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
		return assignRepo, roleRepo, userRepo, tenantRepo, authzRepo, svc
	}

	// 1. Platform admin assigns themselves to Tenant X
	t.Run("1. Platform admin assigns themselves to an existing tenant", func(t *testing.T) {
		assignRepo, _, _, _, _, svc := setup()
		err := svc.AssignTenantRole(ctx, principalAdminA, tenantX, adminA, tenantRoleID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if assignRepo.tenantAssignments[adminA][tenantX] != tenantRoleID {
			t.Fatal("expected tenant assignment in tenantX for adminA")
		}
	})

	// 2. Platform admin assigns themselves to multiple tenants (Tenant X and Tenant Y)
	t.Run("2. Platform admin assigns themselves to multiple tenants", func(t *testing.T) {
		assignRepo, _, _, _, _, svc := setup()
		if err := svc.AssignTenantRole(ctx, principalAdminA, tenantX, adminA, tenantRoleID); err != nil {
			t.Fatalf("unexpected error assigning to tenantX: %v", err)
		}
		if err := svc.AssignTenantRole(ctx, principalAdminA, tenantY, adminA, tenantRoleID); err != nil {
			t.Fatalf("unexpected error assigning to tenantY: %v", err)
		}
		if assignRepo.tenantAssignments[adminA][tenantX] != tenantRoleID ||
			assignRepo.tenantAssignments[adminA][tenantY] != tenantRoleID {
			t.Fatal("expected tenant assignments in both tenantX and tenantY")
		}
	})

	// 3. Platform admin assigns another platform admin to Tenant X
	t.Run("3. Platform admin assigns another platform admin to a tenant", func(t *testing.T) {
		assignRepo, _, _, _, _, svc := setup()
		err := svc.AssignTenantRole(ctx, principalAdminA, tenantX, adminB, tenantRoleID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if assignRepo.tenantAssignments[adminB][tenantX] != tenantRoleID {
			t.Fatal("expected tenant assignment in tenantX for adminB")
		}
	})

	// 4. Platform admin assigns ordinary user to Tenant X
	t.Run("4. Platform admin assigns ordinary user to a tenant", func(t *testing.T) {
		assignRepo, _, _, _, _, svc := setup()
		err := svc.AssignTenantRole(ctx, principalAdminA, tenantX, ordinaryUser, tenantRoleID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if assignRepo.tenantAssignments[ordinaryUser][tenantX] != tenantRoleID {
			t.Fatal("expected tenant assignment in tenantX for ordinaryUser")
		}
	})

	// 5. Platform admin assigns a valid custom role belonging to the target tenant
	t.Run("5. Platform admin assigns a valid custom role belonging to target tenant", func(t *testing.T) {
		assignRepo, roleRepo, _, _, _, svc := setup()
		customRoleID := uuid.New()
		roleRepo.roles[customRoleID] = &model.Role{
			ID:       customRoleID,
			Name:     "CUSTOM_ANALYST",
			Scope:    model.RoleScopeCustomTenant,
			TenantID: &tenantX,
		}

		err := svc.AssignTenantRole(ctx, principalAdminA, tenantX, ordinaryUser, customRoleID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if assignRepo.tenantAssignments[ordinaryUser][tenantX] != customRoleID {
			t.Fatal("expected custom role assigned in tenantX")
		}
	})

	// 6. Platform admin cannot assign a custom role owned by another tenant
	t.Run("6. Platform admin cannot assign a custom role owned by another tenant", func(t *testing.T) {
		_, roleRepo, _, _, _, svc := setup()
		customRoleY := uuid.New()
		roleRepo.roles[customRoleY] = &model.Role{
			ID:       customRoleY,
			Name:     "CUSTOM_Y",
			Scope:    model.RoleScopeCustomTenant,
			TenantID: &tenantY, // belongs to tenant Y, not X
		}

		err := svc.AssignTenantRole(ctx, principalAdminA, tenantX, ordinaryUser, customRoleY)
		if !errors.Is(err, service.ErrInvalidRoleForTenant) {
			t.Fatalf("expected ErrInvalidRoleForTenant, got: %v", err)
		}
	})

	// 7. Platform admin tenant membership operations do not modify platform-role assignments
	t.Run("7. Platform admin tenant membership operations do not modify platform-role assignments", func(t *testing.T) {
		assignRepo, _, _, _, _, svc := setup()
		initialPlatRole := assignRepo.platformAssignments[adminA]
		if initialPlatRole == uuid.Nil {
			t.Fatal("precondition failed: adminA must have a platform role")
		}

		err := svc.AssignTenantRole(ctx, principalAdminA, tenantX, adminA, tenantRoleID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if assignRepo.platformAssignments[adminA] != initialPlatRole {
			t.Fatal("platform role was modified by tenant assignment!")
		}
	})

	// 8. Platform admin without tenant membership cannot exercise tenant-scoped permissions
	t.Run("8. Platform admin without tenant membership cannot exercise tenant permissions", func(t *testing.T) {
		holder := authorization.NewSnapshotHolder()
		engine := authorization.NewLocalEngine(holder)

		platAdminID := adminA.String()
		platRoleID := uuid.New().String()

		snap := &authorization.PolicySnapshot{
			Version:   1,
			CreatedAt: time.Now(),
			Users: map[string]authorization.UserPolicy{
				platAdminID: {Active: true},
			},
			PlatformAssignments: map[string]string{
				platAdminID: platRoleID,
			},
			TenantAssignments: map[string]map[string]string{}, // No tenant assignment!
			Roles: map[string]authorization.RolePolicy{
				platRoleID: {
					ID:          platRoleID,
					Scope:       authorization.RoleScopePlatform,
					Permissions: []string{authorization.PermPlatformRoleAssign},
				},
			},
			Permissions: map[string]authorization.PermissionDefinition{
				authorization.PermTenantUserRead: {Name: authorization.PermTenantUserRead, Scope: authorization.ScopeTenant},
			},
		}
		_ = holder.Set(snap)

		dec, _ := engine.Authorize(ctx, authorization.AuthorizationRequest{
			Principal:  principalAdminA,
			Permission: authorization.PermTenantUserRead,
			TenantID:   tenantX.String(),
		})
		if dec.Allowed {
			t.Fatal("platform admin without tenant membership must be denied tenant-scoped permissions")
		}
		if dec.Reason != authorization.ReasonNoTenantRole {
			t.Fatalf("expected ReasonNoTenantRole, got %s", dec.Reason)
		}
	})

	// 9. Tenant admin cannot use platform-wide existing-user membership operation
	t.Run("9. Tenant admin cannot use cross-tenant membership operation", func(t *testing.T) {
		_, _, _, _, authzRepo, svc := setup()
		tenantAdminID := uuid.New()
		principalTenantAdmin := &identity.Principal{
			UserID:    tenantAdminID,
			SessionID: uuid.New(),
			TokenID:   uuid.New(),
		}
		// Tenant admin only has tenant.user.assign_role in tenantX
		authzRepo.grantTenant(tenantAdminID, tenantX, authorization.PermTenantUserAssignRole)

		// Attempting to assign membership in tenantY must fail with ErrForbidden
		err := svc.AssignTenantRole(ctx, principalTenantAdmin, tenantY, ordinaryUser, tenantRoleID)
		if !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("expected ErrForbidden for cross-tenant assignment, got: %v", err)
		}
	})

	// 10. Tenant admin cannot modify platform-role assignments
	t.Run("10. Tenant admin cannot modify platform-role assignments", func(t *testing.T) {
		_, _, _, _, authzRepo, svc := setup()
		tenantAdminID := uuid.New()
		principalTenantAdmin := &identity.Principal{
			UserID:    tenantAdminID,
			SessionID: uuid.New(),
			TokenID:   uuid.New(),
		}
		authzRepo.grantTenant(tenantAdminID, tenantX, authorization.PermTenantUserAssignRole)

		err := svc.AssignPlatformRole(ctx, principalTenantAdmin, ordinaryUser, uuid.New())
		if !errors.Is(err, service.ErrForbidden) {
			t.Fatalf("expected ErrForbidden when tenant admin modifies platform role, got: %v", err)
		}
	})
}

func TestRoleAssignmentService_ReadOperations(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	tenantID := uuid.New()
	roleID := uuid.New()

	assignRepo := newMockRoleAssignmentRepo()
	roleRepo := newMockRoleRepository()
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()
	authzRepo := newMockAuthorizationRepository()
	svc, _ := service.NewRoleAssignmentService(assignRepo, roleRepo, userRepo, tenantRepo, authzRepo)

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
		assignRepo.tenantAssignments[userID] = map[uuid.UUID]uuid.UUID{
			tenantID: roleID,
		}
		assignRepo.roles[roleID] = &model.Role{ID: roleID, Name: "TENANT_MEMBER"}

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
