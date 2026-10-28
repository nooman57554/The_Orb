package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

type AssignmentScope string

const (
	AssignmentScopePlatform AssignmentScope = "platform"
	AssignmentScopeTenant   AssignmentScope = "tenant"
)

type AssignRoleRequest struct {
	Scope    AssignmentScope `json:"scope"`
	UserID   uuid.UUID       `json:"user_id"`
	RoleID   uuid.UUID       `json:"role_id"`
	TenantID uuid.UUID       `json:"tenant_id,omitempty"`
}

type RemoveRoleRequest struct {
	Scope    AssignmentScope `json:"scope"`
	UserID   uuid.UUID       `json:"user_id"`
	TenantID uuid.UUID       `json:"tenant_id,omitempty"`
}

// RoleAssignmentService consolidates all platform and tenant role assignment operations.
type RoleAssignmentService struct {
	roleAssignRepo repository.RoleAssignmentRepository
	roleRepo       repository.RoleRepository
	userRepo       repository.UserRepository
	tenantRepo     repository.TenantRepository
	authzRepo      repository.AuthorizationRepository
	authzService   *AuthorizationService
}

func NewRoleAssignmentService(
	roleAssignRepo repository.RoleAssignmentRepository,
	roleRepo repository.RoleRepository,
	userRepo repository.UserRepository,
	tenantRepo repository.TenantRepository,
	authzRepo repository.AuthorizationRepository,
	authzService *AuthorizationService,
) (*RoleAssignmentService, error) {
	if roleAssignRepo == nil || roleRepo == nil || userRepo == nil || tenantRepo == nil || authzRepo == nil || authzService == nil {
		return nil, fmt.Errorf("role assignment service dependencies are required")
	}

	return &RoleAssignmentService{
		roleAssignRepo: roleAssignRepo,
		roleRepo:       roleRepo,
		userRepo:       userRepo,
		tenantRepo:     tenantRepo,
		authzRepo:      authzRepo,
		authzService:   authzService,
	}, nil
}

// AssignRole assigns or replaces a role assignment in either platform or tenant scope.
func (s *RoleAssignmentService) AssignRole(
	ctx context.Context,
	actor *identity.Principal,
	req AssignRoleRequest,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}
	if req.UserID == uuid.Nil || req.RoleID == uuid.Nil {
		return fmt.Errorf("user ID and role ID are required")
	}

	switch req.Scope {
	case AssignmentScopePlatform:
		return s.assignPlatformRole(ctx, actor, req)
	case AssignmentScopeTenant:
		return s.assignTenantRole(ctx, actor, req)
	default:
		return fmt.Errorf("invalid assignment scope: %q", req.Scope)
	}
}

func (s *RoleAssignmentService) assignPlatformRole(
	ctx context.Context,
	actor *identity.Principal,
	req AssignRoleRequest,
) error {
	// Invariant: A platform admin may not change or remove their own platform role
	if actor.UserID == req.UserID {
		return ErrCannotModifyOwnPlatformRole
	}

	// Authorize: Only an authorized platform admin may manage other users' platform roles
	if err := s.authzService.AuthorizePlatform(ctx, actor, "role.assign"); err != nil {
		return err
	}

	// Target role must exist and be platform-scoped
	targetRole, err := s.roleRepo.GetByID(ctx, req.RoleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get target role: %w", err)
	}
	if targetRole.Scope != model.RoleScopePlatform {
		return ErrInvalidPlatformRole
	}

	// Target user must exist and be active
	targetUser, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("get target user: %w", err)
	}
	if targetUser == nil {
		return repository.ErrNotFound
	}
	if targetUser.Status != "active" {
		return ErrInactiveUser
	}

	// Last-platform-admin check and assignment
	currentRole, err := s.roleAssignRepo.GetPlatformRole(ctx, req.UserID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("get current platform role: %w", err)
	}
	if err == nil && currentRole != nil && currentRole.Name == "PLATFORM_ADMIN" && targetRole.Name != "PLATFORM_ADMIN" {
		count, err := s.roleAssignRepo.CountPlatformAdmins(ctx)
		if err != nil {
			return fmt.Errorf("count platform admins: %w", err)
		}
		if count <= 1 {
			return ErrCannotRemoveLastPlatformAdmin
		}
	}

	if err := s.roleAssignRepo.AssignPlatformRole(ctx, req.UserID, req.RoleID); err != nil {
		if errors.Is(err, repository.ErrLastPlatformAdmin) {
			return ErrCannotRemoveLastPlatformAdmin
		}
		return err
	}

	return nil
}

func (s *RoleAssignmentService) assignTenantRole(
	ctx context.Context,
	actor *identity.Principal,
	req AssignRoleRequest,
) error {
	if req.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required for tenant scope")
	}

	// Target tenant must exist and be active
	tenant, err := s.tenantRepo.GetByID(ctx, req.TenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("get tenant: %w", err)
	}
	if tenant.Status != "active" {
		return ErrInactiveTenant
	}

	// Target user must exist and be active
	targetUser, err := s.userRepo.GetByID(ctx, req.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("get target user: %w", err)
	}
	if targetUser == nil {
		return repository.ErrNotFound
	}
	if targetUser.Status != "active" {
		return ErrInactiveUser
	}

	// Target role validation
	targetRole, err := s.roleRepo.GetByID(ctx, req.RoleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get role: %w", err)
	}
	if targetRole.Scope == model.RoleScopePlatform {
		return ErrInvalidPermissionScope
	}
	if targetRole.Scope == model.RoleScopeCustomTenant {
		if targetRole.TenantID == nil || *targetRole.TenantID != req.TenantID {
			return ErrRoleNotFound
		}
	}

	// Authorize actor: platform admins have authority; tenant admins need user.assign_role and must satisfy delegation authority
	isPlatformAdmin, err := s.authzRepo.HasPlatformPermission(ctx, actor.UserID, "role.assign")
	if err != nil {
		return fmt.Errorf("check platform admin status: %w", err)
	}

	if !isPlatformAdmin {
		if err := s.authzService.AuthorizeTenant(ctx, actor, req.TenantID, "user.assign_role"); err != nil {
			return err
		}
		if err := s.checkDelegationAuthority(ctx, actor, req.TenantID, targetRole); err != nil {
			return err
		}
	}

	// Check last active tenant admin protection
	currentRole, err := s.authzRepo.GetTenantRole(ctx, req.UserID, req.TenantID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("get current tenant role: %w", err)
	}
	if err == nil && currentRole != nil {
		if len(currentRole.Permissions) == 0 && currentRole.ID != uuid.Nil {
			perms, pErr := s.roleRepo.GetRolePermissions(ctx, currentRole.ID)
			if pErr != nil {
				return fmt.Errorf("get role permissions: %w", pErr)
			}
			currentRole.Permissions = perms
		}
		if len(targetRole.Permissions) == 0 && targetRole.ID != uuid.Nil {
			perms, pErr := s.roleRepo.GetRolePermissions(ctx, targetRole.ID)
			if pErr != nil {
				return fmt.Errorf("get role permissions: %w", pErr)
			}
			targetRole.Permissions = perms
		}
		if s.isRoleAdmin(currentRole) && !s.isRoleAdmin(targetRole) {
			adminCount, cErr := s.authzRepo.CountActiveTenantAdmins(ctx, req.TenantID)
			if cErr != nil {
				return fmt.Errorf("check admin count: %w", cErr)
			}
			if adminCount <= 1 {
				return ErrCannotRemoveLastAdmin
			}
		}
	}

	if err := s.roleAssignRepo.AssignTenantRole(ctx, req.UserID, req.TenantID, req.RoleID); err != nil {
		if errors.Is(err, repository.ErrLastTenantAdmin) {
			return ErrCannotRemoveLastAdmin
		}
		return err
	}

	return nil
}

// RemoveRole removes a role assignment in either platform or tenant scope.
func (s *RoleAssignmentService) RemoveRole(
	ctx context.Context,
	actor *identity.Principal,
	req RemoveRoleRequest,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}
	if req.UserID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	switch req.Scope {
	case AssignmentScopePlatform:
		return s.removePlatformRole(ctx, actor, req)
	case AssignmentScopeTenant:
		return s.removeTenantRole(ctx, actor, req)
	default:
		return fmt.Errorf("invalid assignment scope: %q", req.Scope)
	}
}

func (s *RoleAssignmentService) removePlatformRole(
	ctx context.Context,
	actor *identity.Principal,
	req RemoveRoleRequest,
) error {
	// Invariant: Platform admin must never remove their own platform role
	if actor.UserID == req.UserID {
		return ErrCannotModifyOwnPlatformRole
	}

	// Authorize actor
	if err := s.authzService.AuthorizePlatform(ctx, actor, "role.assign"); err != nil {
		return err
	}

	// Inspect target user's current platform role
	currentRole, err := s.roleAssignRepo.GetPlatformRole(ctx, req.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("get platform role: %w", err)
	}

	// Last platform admin protection
	if currentRole.Name == "PLATFORM_ADMIN" {
		count, err := s.roleAssignRepo.CountPlatformAdmins(ctx)
		if err != nil {
			return fmt.Errorf("count platform admins: %w", err)
		}
		if count <= 1 {
			return ErrCannotRemoveLastPlatformAdmin
		}
	}

	if err := s.roleAssignRepo.RemovePlatformRole(ctx, req.UserID); err != nil {
		if errors.Is(err, repository.ErrLastPlatformAdmin) {
			return ErrCannotRemoveLastPlatformAdmin
		}
		return err
	}

	return nil
}

func (s *RoleAssignmentService) removeTenantRole(
	ctx context.Context,
	actor *identity.Principal,
	req RemoveRoleRequest,
) error {
	if req.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required for tenant scope")
	}

	// Authorize actor: platform admins or tenant admins with user.delete
	isPlatformAdmin, err := s.authzRepo.HasPlatformPermission(ctx, actor.UserID, "role.assign")
	if err != nil {
		return fmt.Errorf("check platform admin status: %w", err)
	}
	if !isPlatformAdmin {
		if err := s.authzService.AuthorizeTenant(ctx, actor, req.TenantID, "user.delete"); err != nil {
			return err
		}
	}

	// Inspect target user's current tenant role
	currentRole, err := s.authzRepo.GetTenantRole(ctx, req.UserID, req.TenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("get current role: %w", err)
	}

	if len(currentRole.Permissions) == 0 && currentRole.ID != uuid.Nil {
		perms, err := s.roleRepo.GetRolePermissions(ctx, currentRole.ID)
		if err != nil {
			return fmt.Errorf("get role permissions: %w", err)
		}
		currentRole.Permissions = perms
	}

	if s.isRoleAdmin(currentRole) {
		adminCount, err := s.authzRepo.CountActiveTenantAdmins(ctx, req.TenantID)
		if err != nil {
			return fmt.Errorf("check admin count: %w", err)
		}
		if adminCount <= 1 {
			return ErrCannotRemoveLastAdmin
		}
	}

	if err := s.roleAssignRepo.RemoveTenantRole(ctx, req.UserID, req.TenantID); err != nil {
		if errors.Is(err, repository.ErrLastTenantAdmin) {
			return ErrCannotRemoveLastAdmin
		}
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("remove member: %w", err)
	}

	return nil
}

// GetPlatformRole returns a user's current platform role, if any.
func (s *RoleAssignmentService) GetPlatformRole(ctx context.Context, userID uuid.UUID) (*model.Role, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}
	role, err := s.roleAssignRepo.GetPlatformRole(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get platform role: %w", err)
	}
	return role, nil
}

// GetTenantRole returns a user's current role in a tenant, if any.
func (s *RoleAssignmentService) GetTenantRole(ctx context.Context, userID, tenantID uuid.UUID) (*model.Role, error) {
	if userID == uuid.Nil || tenantID == uuid.Nil {
		return nil, fmt.Errorf("user ID and tenant ID are required")
	}
	role, err := s.authzRepo.GetTenantRole(ctx, userID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMemberNotFound
		}
		return nil, fmt.Errorf("get tenant role: %w", err)
	}
	return role, nil
}

// ListUsersByRole lists members belonging to a role in a tenant.
func (s *RoleAssignmentService) ListUsersByRole(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error) {
	if tenantID == uuid.Nil || roleID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID and role ID are required")
	}
	return s.roleAssignRepo.ListUsersByTenantRole(ctx, tenantID, roleID)
}

func (s *RoleAssignmentService) checkDelegationAuthority(
	ctx context.Context,
	actor *identity.Principal,
	tenantID uuid.UUID,
	targetRole *model.Role,
) error {
	isPlatformAdmin, err := s.authzRepo.HasPlatformPermission(ctx, actor.UserID, "role.assign")
	if err != nil {
		return fmt.Errorf("check platform delegation permission: %w", err)
	}
	if isPlatformAdmin {
		return nil
	}

	actorRole, err := s.authzRepo.GetTenantRole(ctx, actor.UserID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrForbidden
		}
		return fmt.Errorf("get actor tenant role: %w", err)
	}

	var actorPerms []model.Permission
	if len(actorRole.Permissions) > 0 {
		actorPerms = actorRole.Permissions
	} else if actorRole.ID != uuid.Nil {
		perms, err := s.roleRepo.GetRolePermissions(ctx, actorRole.ID)
		if err != nil {
			return fmt.Errorf("get actor role permissions: %w", err)
		}
		actorPerms = perms
	}

	var targetPerms []model.Permission
	if len(targetRole.Permissions) > 0 {
		targetPerms = targetRole.Permissions
	} else if targetRole.ID != uuid.Nil {
		perms, err := s.roleRepo.GetRolePermissions(ctx, targetRole.ID)
		if err != nil {
			return fmt.Errorf("get target role permissions: %w", err)
		}
		targetPerms = perms
	}

	actorPermMap := make(map[string]struct{}, len(actorPerms))
	for _, p := range actorPerms {
		actorPermMap[p.Name] = struct{}{}
	}

	for _, p := range targetPerms {
		if _, ok := actorPermMap[p.Name]; !ok {
			return fmt.Errorf("%w: cannot delegate permission %q", ErrCannotDelegateRole, p.Name)
		}
	}

	return nil
}

func (s *RoleAssignmentService) isRoleAdmin(role *model.Role) bool {
	if role == nil {
		return false
	}
	if role.Name == "TENANT_ADMIN_RW" || role.Name == "PLATFORM_ADMIN" {
		return true
	}
	for _, p := range role.Permissions {
		if p.Name == "user.assign_role" || p.Name == "role.assign" {
			return true
		}
	}
	return false
}
