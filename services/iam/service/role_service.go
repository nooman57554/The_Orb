package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

var (
	ErrInvalidRoleName        = errors.New("invalid role name: cannot be empty")
	ErrPrivilegeEscalation    = errors.New("cannot grant platform permissions to tenant custom roles")
	ErrInvalidPermissionScope = errors.New("one or more permissions are invalid or not allowed for tenant scope")
	ErrRoleNotFound           = errors.New("role not found")
)

// AllowedTenantPermissions defines the strict set of permissions eligible for tenant custom roles.
var AllowedTenantPermissions = map[string]struct{}{
	"tenant.read":             {},
	"tenant.update":           {},
	"user.read":               {},
	"user.create":             {},
	"user.update":             {},
	"user.remove":             {},
	"user.assign_role":        {},
	"user.invite":             {},
	"role.read":               {},
	"role.create":             {},
	"role.update":             {},
	"role.delete":             {},
	"role.assign_permissions": {},
	"role.assign":             {},
	"permission.read":         {},
	"agent.read":              {},
	"agent.create":            {},
	"agent.update":            {},
	"agent.delete":            {},
	"workflow.read":           {},
	"workflow.create":         {},
	"workflow.update":         {},
	"workflow.delete":         {},
	"workflow.execute":        {},
}

type RoleService struct {
	roleRepo repository.RoleRepository
	permRepo repository.PermissionRepository
}

func NewRoleService(
	roleRepo repository.RoleRepository,
	permRepo repository.PermissionRepository,
) (*RoleService, error) {

	return &RoleService{
		roleRepo: roleRepo,
		permRepo: permRepo,
	}, nil
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

	// Validate permissions if any provided
	if len(permissionIDs) > 0 {
		perms, err := s.permRepo.GetByIDs(ctx, permissionIDs)
		if err != nil {
			return nil, fmt.Errorf("lookup permissions: %w", err)
		}
		if len(perms) != len(permissionIDs) {
			return nil, ErrInvalidPermissionScope
		}

		for _, p := range perms {
			if _, ok := AllowedTenantPermissions[p.Name]; !ok {
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

	// Validate permissions if provided
	if len(permissionIDs) > 0 {
		perms, err := s.permRepo.GetByIDs(ctx, permissionIDs)
		if err != nil {
			return nil, fmt.Errorf("lookup permissions: %w", err)
		}
		if len(perms) != len(permissionIDs) {
			return nil, ErrInvalidPermissionScope
		}

		for _, p := range perms {
			if _, ok := AllowedTenantPermissions[p.Name]; !ok {
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

func (s *RoleService) ListPlatformRoles(ctx context.Context) ([]model.Role, error) {
	return s.roleRepo.ListPlatform(ctx)
}
