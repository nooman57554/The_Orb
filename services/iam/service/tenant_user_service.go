package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
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

// TenantUserService owns tenant membership listing, member retrieval, and new-user tenant provisioning.
type TenantUserService struct {
	userRepo          repository.UserRepository
	tenantRepo        repository.TenantRepository
	roleRepo          repository.RoleRepository
	roleAssignService *RoleAssignmentService
	authzRepo         repository.AuthorizationRepository
}

func NewTenantUserService(
	userRepo repository.UserRepository,
	tenantRepo repository.TenantRepository,
	roleRepo repository.RoleRepository,
	roleAssignService *RoleAssignmentService,
	authzRepo repository.AuthorizationRepository,
) (*TenantUserService, error) {

	return &TenantUserService{
		userRepo:          userRepo,
		tenantRepo:        tenantRepo,
		roleRepo:          roleRepo,
		roleAssignService: roleAssignService,
		authzRepo:         authzRepo,
	}, nil
}

// ProvisionTenantUser provisions a new global user and initial tenant membership atomically.
func (s *TenantUserService) ProvisionTenantUser(
	ctx context.Context,
	actor *identity.Principal,
	tenantID uuid.UUID,
	email, password string,
	roleID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if actor == nil || !actor.IsValid() {
		return nil, ErrUnauthorized
	}
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

	targetRole, err := s.validateRoleForTenant(ctx, tenantID, roleID)
	if err != nil {
		return nil, err
	}

	// Delegation check: if actor is not platform admin, target role's permissions must be a subset of actor's permissions
	isPlatformAdmin, err := s.isPlatformAdmin(ctx, actor.UserID)
	if err != nil {
		return nil, fmt.Errorf("check platform admin status: %w", err)
	}

	if !isPlatformAdmin {
		if err := s.checkRoleDelegation(ctx, actor, tenantID, targetRole); err != nil {
			return nil, err
		}
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

	// Create user, role assignment, and outbox event atomically in transaction
	if err := s.userRepo.CreateWithTenantRole(ctx, user, tenantID, roleID); err != nil {
		if errors.Is(err, repository.ErrDuplicateEmail) {
			return nil, ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("provision tenant user: %w", err)
	}

	return s.userRepo.GetByIDInTenant(ctx, user.ID, tenantID)
}

// AddTenantMember allows an authorized platform admin to assign an existing user to a tenant.
func (s *TenantUserService) AddTenantMember(
	ctx context.Context,
	actor *identity.Principal,
	tenantID, userID, roleID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if err := s.roleAssignService.AssignTenantRole(ctx, actor, tenantID, userID, roleID); err != nil {
		return nil, err
	}
	return s.userRepo.GetByIDInTenant(ctx, userID, tenantID)
}

// ChangeTenantUserRole updates a member's role in a tenant.
func (s *TenantUserService) ChangeTenantUserRole(
	ctx context.Context,
	actor *identity.Principal,
	tenantID, userID, newRoleID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if err := s.roleAssignService.AssignTenantRole(ctx, actor, tenantID, userID, newRoleID); err != nil {
		return nil, err
	}
	return s.userRepo.GetByIDInTenant(ctx, userID, tenantID)
}

// RemoveTenantMember removes a user's membership from a tenant.
func (s *TenantUserService) RemoveTenantMember(
	ctx context.Context,
	actor *identity.Principal,
	tenantID, userID uuid.UUID,
) error {
	return s.roleAssignService.RemoveTenantRole(ctx, actor, tenantID, userID)
}

// ListTenantMembers lists members of a tenant with pagination.
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

// GetTenantMember retrieves a specific member of a tenant.
func (s *TenantUserService) GetTenantMember(
	ctx context.Context,
	tenantID, userID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if tenantID == uuid.Nil || userID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID and user ID are required")
	}
	rec, err := s.userRepo.GetByIDInTenant(ctx, userID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMemberNotFound
		}
		return nil, fmt.Errorf("get tenant member: %w", err)
	}
	return rec, nil
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

func (s *TenantUserService) isPlatformAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.authzRepo.HasPlatformPermission(ctx, userID, authorization.PermPlatformRoleAssign)
}

func (s *TenantUserService) checkRoleDelegation(
	ctx context.Context,
	actor *identity.Principal,
	tenantID uuid.UUID,
	targetRole *model.Role,
) error {
	actorRole, err := s.authzRepo.GetTenantRole(ctx, actor.UserID, tenantID)
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
