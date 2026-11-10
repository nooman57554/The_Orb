package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
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
}

func NewRoleAssignmentService(
	roleAssignRepo repository.RoleAssignmentRepository,
	roleRepo repository.RoleRepository,
	userRepo repository.UserRepository,
	tenantRepo repository.TenantRepository,
	authzRepo repository.AuthorizationRepository,
) (*RoleAssignmentService, error) {
	if roleAssignRepo == nil || roleRepo == nil || userRepo == nil || tenantRepo == nil || authzRepo == nil {
		return nil, fmt.Errorf("role assignment service dependencies are required")
	}

	return &RoleAssignmentService{
		roleAssignRepo: roleAssignRepo,
		roleRepo:       roleRepo,
		userRepo:       userRepo,
		tenantRepo:     tenantRepo,
		authzRepo:      authzRepo,
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
		return s.AssignPlatformRole(ctx, actor, req.UserID, req.RoleID)
	case AssignmentScopeTenant:
		return s.AssignTenantRole(ctx, actor, req.TenantID, req.UserID, req.RoleID)
	default:
		return fmt.Errorf("invalid assignment scope: %q", req.Scope)
	}
}

// AssignPlatformRole assigns or replaces another user's platform role.
// Only an authorized platform admin may assign platform roles.
// Self-demotion is prevented: a platform admin cannot modify their own platform role.
func (s *RoleAssignmentService) AssignPlatformRole(
	ctx context.Context,
	actor *identity.Principal,
	targetUserID, roleID uuid.UUID,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}
	if targetUserID == uuid.Nil || roleID == uuid.Nil {
		return fmt.Errorf("target user ID and role ID are required")
	}

	// Invariant: Platform admin cannot modify their own platform role
	if actor.UserID == targetUserID {
		return ErrCannotModifyOwnPlatformRole
	}

	// Authorize actor: must hold platform.role.assign
	isPlatformAdmin, err := s.isPlatformAdmin(ctx, actor.UserID)
	if err != nil {
		return fmt.Errorf("check platform admin authority: %w", err)
	}
	if !isPlatformAdmin {
		return ErrForbidden
	}

	// Validate target role exists and has platform scope
	targetRole, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get target role: %w", err)
	}
	if targetRole.Scope != model.RoleScopePlatform {
		return ErrInvalidPlatformRole
	}

	// Validate target user exists and is active
	targetUser, err := s.userRepo.GetByID(ctx, targetUserID)
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

	// Service-level check for last admin invariant (persistence layer also enforces transactionally)
	currentRole, err := s.roleAssignRepo.GetPlatformRole(ctx, targetUserID)
	if err == nil && currentRole != nil && currentRole.Name == "PLATFORM_ADMIN" && targetRole.Name != "PLATFORM_ADMIN" {
		count, err := s.roleAssignRepo.CountPlatformAdmins(ctx)
		if err != nil {
			return fmt.Errorf("count platform admins: %w", err)
		}
		if count <= 1 {
			return ErrCannotRemoveLastPlatformAdmin
		}
	}

	if err := s.roleAssignRepo.AssignPlatformRole(ctx, targetUserID, roleID); err != nil {
		if errors.Is(err, repository.ErrLastPlatformAdmin) {
			return ErrCannotRemoveLastPlatformAdmin
		}
		return err
	}

	return nil
}

// RemovePlatformRole removes another user's platform role.
// Self-demotion is prevented: a platform admin cannot remove their own platform role.
func (s *RoleAssignmentService) RemovePlatformRole(
	ctx context.Context,
	actor *identity.Principal,
	targetUserID uuid.UUID,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}
	if targetUserID == uuid.Nil {
		return fmt.Errorf("target user ID is required")
	}

	// Invariant: Platform admin cannot remove their own platform role
	if actor.UserID == targetUserID {
		return ErrCannotModifyOwnPlatformRole
	}

	// Authorize actor: must hold platform.role.assign
	isPlatformAdmin, err := s.isPlatformAdmin(ctx, actor.UserID)
	if err != nil {
		return fmt.Errorf("check platform admin authority: %w", err)
	}
	if !isPlatformAdmin {
		return ErrForbidden
	}

	currentRole, err := s.roleAssignRepo.GetPlatformRole(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("get platform role: %w", err)
	}

	if currentRole.Name == "PLATFORM_ADMIN" {
		count, err := s.roleAssignRepo.CountPlatformAdmins(ctx)
		if err != nil {
			return fmt.Errorf("count platform admins: %w", err)
		}
		if count <= 1 {
			return ErrCannotRemoveLastPlatformAdmin
		}
	}

	if err := s.roleAssignRepo.RemovePlatformRole(ctx, targetUserID); err != nil {
		if errors.Is(err, repository.ErrLastPlatformAdmin) {
			return ErrCannotRemoveLastPlatformAdmin
		}
		return err
	}

	return nil
}

// AssignTenantRole assigns or replaces a user's role in a tenant.
// Authoritative rules:
// - A platform admin can assign themselves or any other user (including another platform admin) to any existing tenant.
// - A tenant admin can only assign roles in their own tenant, subject to delegation rules.
func (s *RoleAssignmentService) AssignTenantRole(
	ctx context.Context,
	actor *identity.Principal,
	tenantID, targetUserID, roleID uuid.UUID,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}
	if tenantID == uuid.Nil || targetUserID == uuid.Nil || roleID == uuid.Nil {
		return fmt.Errorf("tenant ID, target user ID, and role ID are required")
	}

	// 1. Verify tenant exists and is active
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrTenantNotFound
		}
		return fmt.Errorf("get tenant: %w", err)
	}
	if tenant.Status != "active" {
		return ErrInactiveTenant
	}

	// 2. Verify target user exists and is active
	targetUser, err := s.userRepo.GetByID(ctx, targetUserID)
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

	// 3. Verify target role exists, is not platform-scoped, and custom role belongs to this tenant
	targetRole, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get role: %w", err)
	}
	if targetRole.Scope == model.RoleScopePlatform {
		return ErrPrivilegeEscalation
	}
	if targetRole.Scope == model.RoleScopeCustomTenant {
		if targetRole.TenantID == nil || *targetRole.TenantID != tenantID {
			return ErrInvalidRoleForTenant
		}
	}

	// 4. Authorize Actor
	isPlatformAdmin, err := s.isPlatformAdmin(ctx, actor.UserID)
	if err != nil {
		return fmt.Errorf("check platform admin status: %w", err)
	}

	if !isPlatformAdmin {
		// Tenant admins: must have tenant.user.assign_role in this tenant
		hasPerm, err := s.authzRepo.HasTenantPermission(ctx, actor.UserID, tenantID, authorization.PermTenantUserAssignRole)
		if err != nil {
			return fmt.Errorf("check tenant permission: %w", err)
		}
		if !hasPerm {
			return ErrForbidden
		}

		// Enforce delegation rule: target role permissions must be a subset of actor's permissions
		if err := s.checkDelegationAuthority(ctx, actor, tenantID, targetRole); err != nil {
			return err
		}
	}

	// 5. Check last active tenant admin protection (precheck, repository enforces transactionally)
	currentRole, err := s.roleAssignRepo.GetTenantRole(ctx, targetUserID, tenantID)
	if err == nil && currentRole != nil {
		if currentRole.Name == "TENANT_ADMIN_RW" && targetRole.Name != "TENANT_ADMIN_RW" {
			adminCount, cErr := s.roleAssignRepo.CountActiveTenantAdmins(ctx, tenantID)
			if cErr != nil {
				return fmt.Errorf("check admin count: %w", cErr)
			}
			if adminCount <= 1 {
				return ErrCannotRemoveLastAdmin
			}
		}
	}

	if err := s.roleAssignRepo.AssignTenantRole(ctx, targetUserID, tenantID, roleID); err != nil {
		if errors.Is(err, repository.ErrLastTenantAdmin) {
			return ErrCannotRemoveLastAdmin
		}
		return err
	}

	return nil
}

// RemoveTenantRole removes a user's membership from a tenant.
func (s *RoleAssignmentService) RemoveTenantRole(
	ctx context.Context,
	actor *identity.Principal,
	tenantID, targetUserID uuid.UUID,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}
	if tenantID == uuid.Nil || targetUserID == uuid.Nil {
		return fmt.Errorf("tenant ID and user ID are required")
	}

	// Authorize actor: platform admins or tenant admins with tenant.user.remove
	isPlatformAdmin, err := s.isPlatformAdmin(ctx, actor.UserID)
	if err != nil {
		return fmt.Errorf("check platform admin status: %w", err)
	}

	if !isPlatformAdmin {
		hasPerm, err := s.authzRepo.HasTenantPermission(ctx, actor.UserID, tenantID, authorization.PermTenantUserRemove)
		if err != nil {
			return fmt.Errorf("check tenant permission: %w", err)
		}
		if !hasPerm {
			return ErrForbidden
		}
	}

	currentRole, err := s.roleAssignRepo.GetTenantRole(ctx, targetUserID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("get current role: %w", err)
	}

	if currentRole.Name == "TENANT_ADMIN_RW" {
		adminCount, err := s.roleAssignRepo.CountActiveTenantAdmins(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("check admin count: %w", err)
		}
		if adminCount <= 1 {
			return ErrCannotRemoveLastAdmin
		}
	}

	if err := s.roleAssignRepo.RemoveTenantRole(ctx, targetUserID, tenantID); err != nil {
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
		return s.RemovePlatformRole(ctx, actor, req.UserID)
	case AssignmentScopeTenant:
		return s.RemoveTenantRole(ctx, actor, req.TenantID, req.UserID)
	default:
		return fmt.Errorf("invalid assignment scope: %q", req.Scope)
	}
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
	role, err := s.roleAssignRepo.GetTenantRole(ctx, userID, tenantID)
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

func (s *RoleAssignmentService) isPlatformAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.authzRepo.HasPlatformPermission(ctx, userID, authorization.PermPlatformRoleAssign)
}

func (s *RoleAssignmentService) checkDelegationAuthority(
	ctx context.Context,
	actor *identity.Principal,
	tenantID uuid.UUID,
	targetRole *model.Role,
) error {
	actorRole, err := s.roleAssignRepo.GetTenantRole(ctx, actor.UserID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrForbidden
		}
		return fmt.Errorf("get actor tenant role: %w", err)
	}

	actorPerms, err := s.roleRepo.GetRolePermissions(ctx, actorRole.ID)
	if err != nil {
		return fmt.Errorf("get actor role permissions: %w", err)
	}

	targetPerms, err := s.roleRepo.GetRolePermissions(ctx, targetRole.ID)
	if err != nil {
		return fmt.Errorf("get target role permissions: %w", err)
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
