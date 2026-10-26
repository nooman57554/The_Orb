package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

var (
	ErrInvalidRoleName               = errors.New("invalid role name: cannot be empty")
	ErrPrivilegeEscalation           = errors.New("cannot grant platform permissions to tenant custom roles")
	ErrInvalidPermissionScope        = errors.New("one or more permissions are invalid or not allowed for tenant scope")
	ErrRoleNotFound                  = errors.New("role not found")
	ErrCannotModifyOwnPlatformRole   = errors.New("cannot change or remove your own platform role")
	ErrCannotRemoveLastPlatformAdmin = errors.New("cannot remove or demote the last active platform administrator")
	ErrInvalidPlatformRole           = errors.New("role is not a valid platform role")
	ErrCannotDelegateRole            = errors.New("insufficient authority to delegate one or more permissions in the role")
)

type RoleService struct {
	roleRepo       repository.RoleRepository
	permRepo       repository.PermissionRepository
	roleAssignRepo repository.RoleAssignmentRepository
	authzService   *AuthorizationService
	userRepo       repository.UserRepository
}

func NewRoleService(
	roleRepo repository.RoleRepository,
	permRepo repository.PermissionRepository,
	roleAssignRepo repository.RoleAssignmentRepository,
	authzService *AuthorizationService,
	userRepo repository.UserRepository,
) (*RoleService, error) {

	return &RoleService{
		roleRepo:       roleRepo,
		permRepo:       permRepo,
		roleAssignRepo: roleAssignRepo,
		authzService:   authzService,
		userRepo:       userRepo,
	}, nil
}

func (s *RoleService) ListPlatformRoles(ctx context.Context) ([]model.Role, error) {
	return s.roleRepo.ListPlatform(ctx)
}

func (s *RoleService) ListTenantRoles(ctx context.Context, tenantID uuid.UUID) ([]model.Role, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID is required")
	}
	return s.roleRepo.ListByTenant(ctx, tenantID)
}

func (s *RoleService) GetTenantRole(ctx context.Context, tenantID, roleID uuid.UUID) (*model.Role, error) {
	if tenantID == uuid.Nil || roleID == uuid.Nil {
		return nil, ErrRoleNotFound
	}

	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}

	// Verify tenant ownership / scope
	if role.Scope == model.RoleScopeSystemTenant {
		return role, nil
	}
	if role.Scope == model.RoleScopeCustomTenant && role.TenantID != nil && *role.TenantID == tenantID {
		return role, nil
	}

	// Role does not belong to this tenant or is a platform role
	return nil, ErrRoleNotFound
}

func (s *RoleService) CreateCustomTenantRole(
	ctx context.Context,
	tenantID uuid.UUID,
	name, description string,
	permissionIDs []uuid.UUID,
) (*model.Role, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidRoleName
	}
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID is required")
	}

	// Validate permissions if any provided against the authoritative database catalog
	if len(permissionIDs) > 0 {
		perms, err := s.permRepo.GetByIDs(ctx, permissionIDs)
		if err != nil {
			return nil, fmt.Errorf("lookup permissions: %w", err)
		}
		if len(perms) != len(permissionIDs) {
			return nil, ErrInvalidPermissionScope
		}

		for _, p := range perms {
			if p.Scope != "tenant" {
				return nil, ErrPrivilegeEscalation
			}
		}
	}

	role := &model.Role{
		Name:        name,
		Scope:       model.RoleScopeCustomTenant,
		TenantID:    &tenantID,
		Description: strings.TrimSpace(description),
	}

	if err := s.roleRepo.CreateCustom(ctx, role, permissionIDs); err != nil {
		return nil, err
	}

	return s.roleRepo.GetByID(ctx, role.ID)
}

func (s *RoleService) UpdateCustomTenantRole(
	ctx context.Context,
	tenantID, roleID uuid.UUID,
	name, description string,
	permissionIDs []uuid.UUID,
) (*model.Role, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidRoleName
	}
	if tenantID == uuid.Nil || roleID == uuid.Nil {
		return nil, ErrRoleNotFound
	}

	// Validate permissions if provided against authoritative database catalog
	if len(permissionIDs) > 0 {
		perms, err := s.permRepo.GetByIDs(ctx, permissionIDs)
		if err != nil {
			return nil, fmt.Errorf("lookup permissions: %w", err)
		}
		if len(perms) != len(permissionIDs) {
			return nil, ErrInvalidPermissionScope
		}

		for _, p := range perms {
			if p.Scope != "tenant" {
				return nil, ErrPrivilegeEscalation
			}
		}
	}

	role := &model.Role{
		ID:          roleID,
		Name:        name,
		Scope:       model.RoleScopeCustomTenant,
		TenantID:    &tenantID,
		Description: strings.TrimSpace(description),
	}

	if err := s.roleRepo.UpdateCustom(ctx, role, permissionIDs); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}

	return s.roleRepo.GetByID(ctx, roleID)
}

func (s *RoleService) DeleteCustomTenantRole(
	ctx context.Context,
	tenantID, roleID uuid.UUID,
) error {
	if tenantID == uuid.Nil || roleID == uuid.Nil {
		return ErrRoleNotFound
	}

	err := s.roleRepo.DeleteCustom(ctx, roleID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrRoleNotFound
		}
		return err
	}

	return nil
}

// AssignPlatformRole allows an authorized platform admin to assign or replace another user's platform role.
func (s *RoleService) AssignPlatformRole(
	ctx context.Context,
	actor *identity.Principal,
	targetUserID uuid.UUID,
	roleID uuid.UUID,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}
	if targetUserID == uuid.Nil || roleID == uuid.Nil {
		return fmt.Errorf("target user ID and role ID are required")
	}

	// 1. Authorize: Actor must be an authorized platform admin
	if err := s.authzService.AuthorizePlatform(ctx, actor, "role.assign"); err != nil {
		return err
	}

	// 2. Invariant: Platform admin must never change or remove their own platform role
	if actor.UserID == targetUserID {
		return ErrCannotModifyOwnPlatformRole
	}

	// 3. Target role must exist and be platform-scoped
	targetRole, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("get role: %w", err)
	}
	if targetRole.Scope != model.RoleScopePlatform {
		return ErrInvalidPlatformRole
	}

	// 4. Target user must exist
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

	// 5. If target user currently has PLATFORM_ADMIN and the new role is not PLATFORM_ADMIN,
	// protect against removing/demoting the last active platform admin
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

	return s.roleAssignRepo.AssignPlatformRole(ctx, targetUserID, roleID)
}

// RemovePlatformRole allows an authorized platform admin to remove another user's platform role.
func (s *RoleService) RemovePlatformRole(
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

	// 1. Authorize: Actor must be an authorized platform admin
	if err := s.authzService.AuthorizePlatform(ctx, actor, "role.assign"); err != nil {
		return err
	}

	// 2. Invariant: Platform admin must never remove their own platform role
	if actor.UserID == targetUserID {
		return ErrCannotModifyOwnPlatformRole
	}

	// 3. Inspect target user's current platform role
	currentRole, err := s.roleAssignRepo.GetPlatformRole(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("get platform role: %w", err)
	}

	// 4. If target is a PLATFORM_ADMIN, protect the last platform admin
	if currentRole.Name == "PLATFORM_ADMIN" {
		count, err := s.roleAssignRepo.CountPlatformAdmins(ctx)
		if err != nil {
			return fmt.Errorf("count platform admins: %w", err)
		}
		if count <= 1 {
			return ErrCannotRemoveLastPlatformAdmin
		}
	}

	return s.roleAssignRepo.RemovePlatformRole(ctx, targetUserID)
}

// GetPlatformRole returns a user's current platform role, if any.
func (s *RoleService) GetPlatformRole(ctx context.Context, targetUserID uuid.UUID) (*model.Role, error) {
	if targetUserID == uuid.Nil {
		return nil, fmt.Errorf("target user ID is required")
	}
	role, err := s.roleAssignRepo.GetPlatformRole(ctx, targetUserID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	perms, err := s.roleRepo.GetRolePermissions(ctx, role.ID)
	if err != nil {
		return nil, fmt.Errorf("get role permissions: %w", err)
	}
	role.Permissions = perms
	return role, nil
}
