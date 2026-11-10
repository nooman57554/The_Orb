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
	ErrRoleHasAssignments            = repository.ErrRoleHasAssignments
)

// RoleService owns role definition lifecycle, custom role scope validation, and permission mappings.
type RoleService struct {
	roleRepo          repository.RoleRepository
	permRepo          repository.PermissionRepository
	roleAssignService *RoleAssignmentService
}

func NewRoleService(
	roleRepo repository.RoleRepository,
	permRepo repository.PermissionRepository,
	roleAssignService ...*RoleAssignmentService,
) (*RoleService, error) {
	if roleRepo == nil || permRepo == nil {
		return nil, fmt.Errorf("role repository and permission repository are required")
	}

	var ras *RoleAssignmentService
	if len(roleAssignService) > 0 {
		ras = roleAssignService[0]
	}

	return &RoleService{
		roleRepo:          roleRepo,
		permRepo:          permRepo,
		roleAssignService: ras,
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

func (s *RoleService) ListPermissions(ctx context.Context) ([]model.Permission, error) {
	return s.permRepo.ListAll(ctx)
}

// Assignment delegation methods forwarding to RoleAssignmentService if injected
func (s *RoleService) AssignPlatformRole(
	ctx context.Context,
	actor *identity.Principal,
	targetUserID uuid.UUID,
	roleID uuid.UUID,
) error {
	if s.roleAssignService != nil {
		return s.roleAssignService.AssignPlatformRole(ctx, actor, targetUserID, roleID)
	}
	return errors.New("role assignment service not configured")
}

func (s *RoleService) RemovePlatformRole(
	ctx context.Context,
	actor *identity.Principal,
	targetUserID uuid.UUID,
) error {
	if s.roleAssignService != nil {
		return s.roleAssignService.RemovePlatformRole(ctx, actor, targetUserID)
	}
	return errors.New("role assignment service not configured")
}

func (s *RoleService) GetPlatformRole(ctx context.Context, targetUserID uuid.UUID) (*model.Role, error) {
	if s.roleAssignService != nil {
		return s.roleAssignService.GetPlatformRole(ctx, targetUserID)
	}
	return nil, errors.New("role assignment service not configured")
}

func (s *RoleService) ListUsersByRole(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error) {
	if s.roleAssignService != nil {
		return s.roleAssignService.ListUsersByRole(ctx, tenantID, roleID)
	}
	return nil, errors.New("role assignment service not configured")
}
