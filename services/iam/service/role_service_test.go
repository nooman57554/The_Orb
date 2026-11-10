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

func TestRoleService_CreateCustomTenantRole_PrivilegeEscalationPrevented(t *testing.T) {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()

	platformPermID := uuid.New()
	permRepo.permissions[platformPermID] = model.Permission{
		ID:    platformPermID,
		Name:  "platform.tenant.create",
		Scope: "platform", // platform-only permission
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
		ID:    tenantPermID,
		Name:  "tenant.user.read",
		Scope: "tenant",
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

func TestRoleService_PlatformAdmin_CannotChangeOwnRole(t *testing.T) {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()
	roleAssignRepo := newMockRoleAssignmentRepo()
	authzRepo := newMockAuthorizationRepository()
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()

	roleAssignSvc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	if err != nil {
		t.Fatalf("failed to create role assignment service: %v", err)
	}

	svc, err := service.NewRoleService(roleRepo, permRepo, roleAssignSvc)
	if err != nil {
		t.Fatalf("failed to create role service: %v", err)
	}

	adminID := uuid.New()
	authzRepo.grantPlatform(adminID, authorization.PermPlatformRoleAssign)

	adminPrincipal := &identity.Principal{
		UserID:    adminID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	roleID := uuid.New()
	roleRepo.roles[roleID] = &model.Role{
		ID:    roleID,
		Name:  "PLATFORM_ADMIN",
		Scope: model.RoleScopePlatform,
	}

	// Attempting to modify own platform role must return ErrCannotModifyOwnPlatformRole
	err = svc.AssignPlatformRole(context.Background(), adminPrincipal, adminID, roleID)
	if !errors.Is(err, service.ErrCannotModifyOwnPlatformRole) {
		t.Fatalf("expected ErrCannotModifyOwnPlatformRole, got %v", err)
	}

	// Attempting to remove own platform role must return ErrCannotModifyOwnPlatformRole
	err = svc.RemovePlatformRole(context.Background(), adminPrincipal, adminID)
	if !errors.Is(err, service.ErrCannotModifyOwnPlatformRole) {
		t.Fatalf("expected ErrCannotModifyOwnPlatformRole on remove, got %v", err)
	}
}

func TestRoleService_PlatformAdmin_CanChangeOtherPlatformAdminRole(t *testing.T) {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()
	roleAssignRepo := newMockRoleAssignmentRepo()
	roleAssignRepo.platformAdminCount = 2 // 2 admins so demotion/change is safe
	authzRepo := newMockAuthorizationRepository()
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()

	roleAssignSvc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	if err != nil {
		t.Fatalf("failed to create role assignment service: %v", err)
	}

	svc, err := service.NewRoleService(roleRepo, permRepo, roleAssignSvc)
	if err != nil {
		t.Fatalf("failed to create role service: %v", err)
	}

	adminA := uuid.New()
	adminB := uuid.New()
	authzRepo.grantPlatform(adminA, authorization.PermPlatformRoleAssign)
	userRepo.users[adminB] = &model.User{ID: adminB, Status: "active"}

	principalA := &identity.Principal{
		UserID:    adminA,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	platformRoleID := uuid.New()
	roleRepo.roles[platformRoleID] = &model.Role{
		ID:    platformRoleID,
		Name:  "PLATFORM_AUDITOR",
		Scope: model.RoleScopePlatform,
	}

	// Admin A successfully assigns platform role to Admin B
	err = svc.AssignPlatformRole(context.Background(), principalA, adminB, platformRoleID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRoleService_PlatformAdmin_LastPlatformAdminProtection(t *testing.T) {
	roleRepo := newMockRoleRepository()
	permRepo := newMockPermissionRepository()
	roleAssignRepo := newMockRoleAssignmentRepo()
	roleAssignRepo.platformAdminCount = 1 // only 1 admin left
	authzRepo := newMockAuthorizationRepository()
	userRepo := newMockUserRepository()
	tenantRepo := newMockTenantRepository()

	roleAssignSvc, err := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	if err != nil {
		t.Fatalf("failed to create role assignment service: %v", err)
	}

	svc, err := service.NewRoleService(roleRepo, permRepo, roleAssignSvc)
	if err != nil {
		t.Fatalf("failed to create role service: %v", err)
	}

	adminA := uuid.New()
	adminB := uuid.New()
	authzRepo.grantPlatform(adminA, authorization.PermPlatformRoleAssign)
	userRepo.users[adminB] = &model.User{ID: adminB, Status: "active"}

	adminRoleID := uuid.New()
	roleRepo.roles[adminRoleID] = &model.Role{
		ID:    adminRoleID,
		Name:  "PLATFORM_ADMIN",
		Scope: model.RoleScopePlatform,
	}
	roleAssignRepo.platformAssignments[adminB] = adminRoleID
	roleAssignRepo.roles[adminRoleID] = roleRepo.roles[adminRoleID]

	auditorRoleID := uuid.New()
	roleRepo.roles[auditorRoleID] = &model.Role{
		ID:    auditorRoleID,
		Name:  "PLATFORM_AUDITOR",
		Scope: model.RoleScopePlatform,
	}

	principalA := &identity.Principal{
		UserID:    adminA,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// Demoting the last platform admin must fail with ErrCannotRemoveLastPlatformAdmin
	err = svc.AssignPlatformRole(context.Background(), principalA, adminB, auditorRoleID)
	if !errors.Is(err, service.ErrCannotRemoveLastPlatformAdmin) {
		t.Fatalf("expected ErrCannotRemoveLastPlatformAdmin on demote, got %v", err)
	}

	// Removing the last platform admin must fail with ErrCannotRemoveLastPlatformAdmin
	err = svc.RemovePlatformRole(context.Background(), principalA, adminB)
	if !errors.Is(err, service.ErrCannotRemoveLastPlatformAdmin) {
		t.Fatalf("expected ErrCannotRemoveLastPlatformAdmin on remove, got %v", err)
	}
}
