package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

func TestTenantUserService_LastAdminProtection(t *testing.T) {
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignmentRepo()
	authzRepo := newMockAuthorizationRepository()

	roleAssignSvc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	if err != nil {
		t.Fatalf("failed to create role assignment service: %v", err)
	}

	tenantID := uuid.New()
	tenantRepo.tenants[tenantID] = &model.Tenant{ID: tenantID, Status: "active"}

	adminRoleID := uuid.New()
	adminRole := &model.Role{
		ID:    adminRoleID,
		Name:  "TENANT_ADMIN_RW",
		Scope: model.RoleScopeSystemTenant,
		Permissions: []model.Permission{
			{Name: authorization.PermTenantUserAssignRole},
			{Name: authorization.PermTenantUserRemove},
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
	_ = userRepo.CreateWithTenantRole(context.Background(), userRepo.users[adminUserID], tenantID, adminRoleID)
	_ = roleAssignRepo.AssignTenantRole(context.Background(), adminUserID, tenantID, adminRoleID)

	tokenID := uuid.New()
	adminPrincipal := &identity.Principal{
		UserID:    adminUserID,
		SessionID: uuid.New(),
		TokenID:   tokenID,
	}

	roleAssignRepo.activeTenantAdmins[tenantID] = 1
	roleAssignRepo.roles[adminRoleID] = adminRole
	authzRepo.tenantRoles[adminUserID] = map[uuid.UUID]*model.Role{tenantID: adminRole}
	authzRepo.grantTenant(adminUserID, tenantID, authorization.PermTenantUserAssignRole)
	authzRepo.grantTenant(adminUserID, tenantID, authorization.PermTenantUserRemove)

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignSvc, authzRepo)
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
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignmentRepo()
	authzRepo := newMockAuthorizationRepository()

	roleAssignSvc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	if err != nil {
		t.Fatalf("failed to create role assignment service: %v", err)
	}

	tenantID := uuid.New()
	tenantRepo.tenants[tenantID] = &model.Tenant{ID: tenantID, Status: "active"}

	// Actor only has tenant.user.read, tenant.user.create, and tenant.user.assign_role
	actorRoleID := uuid.New()
	actorRole := &model.Role{
		ID:       actorRoleID,
		Name:     "LIMITED_ADMIN",
		Scope:    model.RoleScopeCustomTenant,
		TenantID: &tenantID,
		Permissions: []model.Permission{
			{Name: authorization.PermTenantUserRead},
			{Name: authorization.PermTenantUserCreate},
			{Name: authorization.PermTenantUserAssignRole},
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
			{Name: authorization.PermTenantUserRead},
			{Name: authorization.PermWorkflowExecute},
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

	authzRepo.tenantRoles[actorID] = map[uuid.UUID]*model.Role{tenantID: actorRole}
	authzRepo.grantTenant(actorID, tenantID, authorization.PermTenantUserAssignRole)

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignSvc, authzRepo)
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
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignmentRepo()
	authzRepo := newMockAuthorizationRepository()

	roleAssignSvc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	if err != nil {
		t.Fatalf("failed to create role assignment service: %v", err)
	}

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
	// Tenant admin does NOT have platform.role.assign

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignSvc, authzRepo)
	if err != nil {
		t.Fatalf("failed to create tenant user service: %v", err)
	}

	_, err = svc.AddTenantMember(context.Background(), tenantAdminPrincipal, tenantID, targetUserID, roleID)
	if !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for tenant admin adding existing global user, got %v", err)
	}

	// 2. Platform Admin with platform.role.assign is permitted
	platformAdminID := uuid.New()
	token2 := uuid.New()
	platformAdminPrincipal := &identity.Principal{
		UserID:    platformAdminID,
		SessionID: uuid.New(),
		TokenID:   token2,
	}
	authzRepo.grantPlatform(platformAdminID, authorization.PermPlatformRoleAssign)

	member, err := svc.AddTenantMember(context.Background(), platformAdminPrincipal, tenantID, targetUserID, roleID)
	if err != nil {
		t.Fatalf("unexpected error for platform admin adding member: %v", err)
	}
	if member.UserID != targetUserID {
		t.Fatalf("expected member user ID %s, got %s", targetUserID, member.UserID)
	}
}

func TestTenantUserService_ProvisionTenantUser_DuplicateEmailConflict(t *testing.T) {
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()
	roleRepo := newMockRoleRepository()
	roleAssignRepo := newMockRoleAssignmentRepo()
	authzRepo := newMockAuthorizationRepository()

	roleAssignSvc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	if err != nil {
		t.Fatalf("failed to create role assignment service: %v", err)
	}

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
	authzRepo.grantPlatform(adminID, authorization.PermPlatformRoleAssign)

	svc, err := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignSvc, authzRepo)
	if err != nil {
		t.Fatalf("failed to create tenant user service: %v", err)
	}

	// Mock duplicate email return
	userRepo.CreateWithTenantRoleFunc = func(ctx context.Context, user *model.User, tID, rID uuid.UUID) error {
		return repository.ErrDuplicateEmail
	}

	_, err = svc.ProvisionTenantUser(context.Background(), adminPrincipal, tenantID, "duplicate@example.com", "Password123!", roleID)
	if !errors.Is(err, service.ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists on duplicate email, got %v", err)
	}
}
