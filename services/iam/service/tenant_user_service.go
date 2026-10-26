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
	authzService   *AuthorizationService
}

func NewTenantUserService(
	userRepo repository.UserRepository,
	tenantRepo repository.TenantRepository,
	roleRepo repository.RoleRepository,
	roleAssignRepo repository.RoleAssignmentRepository,
	authzRepo repository.AuthorizationRepository,
	sessionRepo repository.SessionRepository,
	authzService *AuthorizationService,
) (*TenantUserService, error) {
	if userRepo == nil {
		return nil, fmt.Errorf("user repository is required")
	}
	if tenantRepo == nil {
		return nil, fmt.Errorf("tenant repository is required")
	}
	if roleRepo == nil {
		return nil, fmt.Errorf("role repository is required")
	}
	if roleAssignRepo == nil {
		return nil, fmt.Errorf("role assignment repository is required")
	}
	if authzRepo == nil {
		return nil, fmt.Errorf("authorization repository is required")
	}
	if sessionRepo == nil {
		return nil, fmt.Errorf("session repository is required")
	}
	if authzService == nil {
		return nil, fmt.Errorf("authorization service is required")
	}

	return &TenantUserService{
		userRepo:       userRepo,
		tenantRepo:     tenantRepo,
		roleRepo:       roleRepo,
		roleAssignRepo: roleAssignRepo,
		authzRepo:      authzRepo,
		sessionRepo:    sessionRepo,
		authzService:   authzService,
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

func (s *TenantUserService) checkRoleDelegation(
	ctx context.Context,
	actor *identity.Principal,
	tenantID uuid.UUID,
	targetRole *model.Role,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}

	// 1. If actor is Platform Admin, they hold platform-wide role.assign and may assign any valid tenant role
	isPlatformAdmin, err := s.authzRepo.HasPlatformPermission(ctx, actor.UserID, "role.assign")
	if err != nil {
		return fmt.Errorf("check platform delegation permission: %w", err)
	}
	if isPlatformAdmin {
		return nil
	}

	// 2. Tenant admins: compare delegable permissions against target role's permissions
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
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return fmt.Errorf("get actor role permissions: %w", err)
		}
		actorPerms = perms
	}

	var targetPerms []model.Permission
	if len(targetRole.Permissions) > 0 {
		targetPerms = targetRole.Permissions
	} else if targetRole.ID != uuid.Nil {
		perms, err := s.roleRepo.GetRolePermissions(ctx, targetRole.ID)
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
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

	// Delegation check: actor must have all permissions granted by targetRole
	if err := s.checkRoleDelegation(ctx, actor, tenantID, targetRole); err != nil {
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

	// Create user and initial tenant role assignment atomically
	if err := s.userRepo.CreateWithTenantRole(ctx, user, tenantID, roleID); err != nil {
		if errors.Is(err, repository.ErrDuplicateEmail) {
			return nil, ErrUserAlreadyExists
		}
		return nil, fmt.Errorf("provision tenant user: %w", err)
	}

	return s.userRepo.GetByIDInTenant(ctx, user.ID, tenantID)
}

// AddTenantMember allows an authorized platform admin to assign a tenant role to an existing user.
// Tenant admins are restricted from searching or adding existing global users directly.
func (s *TenantUserService) AddTenantMember(
	ctx context.Context,
	actor *identity.Principal,
	tenantID, userID, roleID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if actor == nil || !actor.IsValid() {
		return nil, ErrUnauthorized
	}
	if tenantID == uuid.Nil || userID == uuid.Nil || roleID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID, user ID, and role ID are required")
	}

	// Invariant: Only authorized platform admins can assign existing global users to a tenant directly.
	// Tenant admins must not be provided a global user-directory workflow.
	isPlatformAdmin, err := s.authzRepo.HasPlatformPermission(ctx, actor.UserID, "role.assign")
	if err != nil {
		return nil, fmt.Errorf("check platform permission: %w", err)
	}
	if !isPlatformAdmin {
		return nil, ErrForbidden
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

// ChangeTenantUserRole updates a member's role in a tenant, protecting the last active tenant admin.
func (s *TenantUserService) ChangeTenantUserRole(
	ctx context.Context,
	actor *identity.Principal,
	tenantID, userID, newRoleID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if actor == nil || !actor.IsValid() {
		return nil, ErrUnauthorized
	}
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

	// Delegation check: actor must have all permissions granted by newRole
	if err := s.checkRoleDelegation(ctx, actor, tenantID, newRole); err != nil {
		return nil, err
	}

	currentRole, err := s.authzRepo.GetTenantRole(ctx, userID, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrMemberNotFound
		}
		return nil, fmt.Errorf("get current role: %w", err)
	}

	if len(currentRole.Permissions) == 0 && currentRole.ID != uuid.Nil {
		perms, err := s.roleRepo.GetRolePermissions(ctx, currentRole.ID)
		if err == nil {
			currentRole.Permissions = perms
		}
	}

	if len(newRole.Permissions) == 0 && newRole.ID != uuid.Nil {
		newPerms, err := s.roleRepo.GetRolePermissions(ctx, newRole.ID)
		if err == nil {
			newRole.Permissions = newPerms
		}
	}

	// If currently an admin and new role is NOT an admin, check last admin protection
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

// RemoveTenantMember removes a user's membership from a tenant without deleting the global user.
func (s *TenantUserService) RemoveTenantMember(
	ctx context.Context,
	actor *identity.Principal,
	tenantID, userID uuid.UUID,
) error {
	if actor == nil || !actor.IsValid() {
		return ErrUnauthorized
	}
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

	if len(currentRole.Permissions) == 0 && currentRole.ID != uuid.Nil {
		perms, err := s.roleRepo.GetRolePermissions(ctx, currentRole.ID)
		if err == nil {
			currentRole.Permissions = perms
		}
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

	// Removing tenant membership deletes the role assignment row, not the global user
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
