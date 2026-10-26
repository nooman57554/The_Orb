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
	ErrCannotRemoveLastAdmin = errors.New("cannot remove or demote the last active tenant administrator")
	ErrInactiveTenant        = errors.New("tenant is not active")
	ErrInactiveUser          = errors.New("user is not active")
	ErrMemberNotFound        = errors.New("tenant member not found")
	ErrInvalidRoleForTenant  = errors.New("role does not belong to target tenant or is a platform role")
)

type TenantUserService struct {
	userRepo       repository.UserRepository
	tenantRepo     repository.TenantRepository
	roleRepo       repository.RoleRepository
	roleAssignRepo repository.RoleAssignmentRepository
	authzRepo      repository.AuthorizationRepository
	sessionRepo    repository.SessionRepository
}

func NewTenantUserService(
	userRepo repository.UserRepository,
	tenantRepo repository.TenantRepository,
	roleRepo repository.RoleRepository,
	roleAssignRepo repository.RoleAssignmentRepository,
	authzRepo repository.AuthorizationRepository,
	sessionRepo repository.SessionRepository,
) (*TenantUserService, error) {
	if userRepo == nil || tenantRepo == nil || roleRepo == nil || roleAssignRepo == nil || authzRepo == nil || sessionRepo == nil {
		return nil, fmt.Errorf("all repositories are required for TenantUserService")
	}

	return &TenantUserService{
		userRepo:       userRepo,
		tenantRepo:     tenantRepo,
		roleRepo:       roleRepo,
		roleAssignRepo: roleAssignRepo,
		authzRepo:      authzRepo,
		sessionRepo:    sessionRepo,
	}, nil
}

func (s *TenantUserService) validateRoleForTenant(ctx context.Context, tenantID, roleID uuid.UUID) (*model.Role, error) {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("get role: %w", err)
	}

	if role.Scope == model.RoleScopePlatform {
		return nil, ErrPrivilegeEscalation
	}

	if role.Scope == model.RoleScopeCustomTenant {
		if role.TenantID == nil || *role.TenantID != tenantID {
			return nil, ErrInvalidRoleForTenant
		}
	}

	return role, nil
}

func (s *TenantUserService) isRoleAdmin(role *model.Role) bool {
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

func (s *TenantUserService) ProvisionTenantUser(
	ctx context.Context,
	tenantID uuid.UUID,
	email, password string,
	roleID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if tenantID == uuid.Nil || roleID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID and role ID are required")
	}

	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	if tenant.Status != "active" {
		return nil, ErrInactiveTenant
	}

	if _, err := s.validateRoleForTenant(ctx, tenantID, roleID); err != nil {
		return nil, err
	}

	email = strings.ToLower(strings.TrimSpace(email))
	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &model.User{
		Email:        email,
		PasswordHash: passwordHash,
		Status:       "active",
	}

	if err := s.userRepo.CreateWithTenantRole(ctx, user, tenantID, roleID); err != nil {
		if errors.Is(err, repository.ErrDuplicateEmail) {
			return nil, ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("provision tenant user: %w", err)
	}

	return s.userRepo.GetByIDInTenant(ctx, user.ID, tenantID)
}

func (s *TenantUserService) AddTenantMember(
	ctx context.Context,
	tenantID, userID, roleID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if tenantID == uuid.Nil || userID == uuid.Nil || roleID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID, user ID, and role ID are required")
	}

	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	if tenant.Status != "active" {
		return nil, ErrInactiveTenant
	}

	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("get user: %w", err)
	}
	if user.Status != "active" {
		return nil, ErrInactiveUser
	}

	if _, err := s.validateRoleForTenant(ctx, tenantID, roleID); err != nil {
		return nil, err
	}

	if err := s.roleAssignRepo.AssignTenantRole(ctx, userID, tenantID, roleID); err != nil {
		return nil, fmt.Errorf("assign member role: %w", err)
	}

	return s.userRepo.GetByIDInTenant(ctx, userID, tenantID)
}

func (s *TenantUserService) ChangeTenantUserRole(
	ctx context.Context,
	tenantID, userID, newRoleID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if tenantID == uuid.Nil || userID == uuid.Nil || newRoleID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID, user ID, and role ID are required")
	}

	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	if tenant.Status != "active" {
		return nil, ErrInactiveTenant
	}

	newRole, err := s.validateRoleForTenant(ctx, tenantID, newRoleID)
	if err != nil {
		return nil, err
	}

	currentRole, err := s.authzRepo.GetTenantRole(ctx, userID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMemberNotFound
		}
		return nil, fmt.Errorf("get current role: %w", err)
	}

	// If currently an admin and new role is NOT an admin, check last admin protection
	perms, err := s.roleRepo.GetRolePermissions(ctx, currentRole.ID)
	if err == nil {
		currentRole.Permissions = perms
	}
	if s.isRoleAdmin(currentRole) && !s.isRoleAdmin(newRole) {
		adminCount, err := s.authzRepo.CountActiveTenantAdmins(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("check admin count: %w", err)
		}
		if adminCount <= 1 {
			return nil, ErrCannotRemoveLastAdmin
		}
	}

	if err := s.roleAssignRepo.AssignTenantRole(ctx, userID, tenantID, newRoleID); err != nil {
		return nil, fmt.Errorf("update tenant role: %w", err)
	}

	return s.userRepo.GetByIDInTenant(ctx, userID, tenantID)
}

func (s *TenantUserService) RemoveTenantMember(
	ctx context.Context,
	tenantID, userID uuid.UUID,
) error {
	if tenantID == uuid.Nil || userID == uuid.Nil {
		return fmt.Errorf("tenant ID and user ID are required")
	}

	currentRole, err := s.authzRepo.GetTenantRole(ctx, userID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("get current role: %w", err)
	}

	perms, err := s.roleRepo.GetRolePermissions(ctx, currentRole.ID)
	if err == nil {
		currentRole.Permissions = perms
	}
	if s.isRoleAdmin(currentRole) {
		adminCount, err := s.authzRepo.CountActiveTenantAdmins(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("check admin count: %w", err)
		}
		if adminCount <= 1 {
			return ErrCannotRemoveLastAdmin
		}
	}

	if err := s.roleAssignRepo.RemoveTenantRole(ctx, userID, tenantID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrMemberNotFound
		}
		return fmt.Errorf("remove member: %w", err)
	}

	return nil
}

func (s *TenantUserService) ListTenantMembers(
	ctx context.Context,
	tenantID uuid.UUID,
	offset, limit int,
) ([]model.TenantMemberRecord, int, error) {
	if tenantID == uuid.Nil {
		return nil, 0, fmt.Errorf("tenant ID is required")
	}
	return s.userRepo.ListByTenant(ctx, tenantID, offset, limit)
}

func (s *TenantUserService) GetTenantMember(
	ctx context.Context,
	tenantID, userID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if tenantID == uuid.Nil || userID == uuid.Nil {
		return nil, ErrMemberNotFound
	}
	record, err := s.userRepo.GetByIDInTenant(ctx, userID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMemberNotFound
		}
		return nil, fmt.Errorf("get tenant member: %w", err)
	}
	return record, nil
}

func (s *TenantUserService) DeactivateUser(
	ctx context.Context,
	userID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if err := s.userRepo.SetStatus(ctx, userID, "deactivated"); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("deactivate user: %w", err)
	}

	// Revoke all active sessions for this user
	if err := s.sessionRepo.RevokeAllByUserID(ctx, userID); err != nil {
		return fmt.Errorf("revoke user sessions: %w", err)
	}

	return nil
}

func (s *TenantUserService) ReactivateUser(
	ctx context.Context,
	userID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	if err := s.userRepo.SetStatus(ctx, userID, "active"); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("reactivate user: %w", err)
	}

	return nil
}
