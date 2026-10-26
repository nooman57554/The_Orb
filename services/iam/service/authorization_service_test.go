package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockAuthorizationRepository struct {
	platformPerms map[uuid.UUID]map[string]bool
	tenantPerms   map[uuid.UUID]map[uuid.UUID]map[string]bool
	tenantRoles   map[uuid.UUID]map[uuid.UUID]*model.Role
	activeAdmins  map[uuid.UUID]int
	forceError    bool
}

func newMockAuthorizationRepository() *mockAuthorizationRepository {
	return &mockAuthorizationRepository{
		platformPerms: make(map[uuid.UUID]map[string]bool),
		tenantPerms:   make(map[uuid.UUID]map[uuid.UUID]map[string]bool),
		tenantRoles:   make(map[uuid.UUID]map[uuid.UUID]*model.Role),
		activeAdmins:  make(map[uuid.UUID]int),
	}
}

func (m *mockAuthorizationRepository) grantPlatform(userID uuid.UUID, permission string) {
	if m.platformPerms[userID] == nil {
		m.platformPerms[userID] = make(map[string]bool)
	}
	m.platformPerms[userID][permission] = true
}

func (m *mockAuthorizationRepository) grantTenant(userID, tenantID uuid.UUID, permission string) {
	if m.tenantPerms[userID] == nil {
		m.tenantPerms[userID] = make(map[uuid.UUID]map[string]bool)
	}
	if m.tenantPerms[userID][tenantID] == nil {
		m.tenantPerms[userID][tenantID] = make(map[string]bool)
	}
	m.tenantPerms[userID][tenantID][permission] = true
}

func (m *mockAuthorizationRepository) setTenantRole(userID, tenantID uuid.UUID, role *model.Role) {
	if m.tenantRoles[userID] == nil {
		m.tenantRoles[userID] = make(map[uuid.UUID]*model.Role)
	}
	m.tenantRoles[userID][tenantID] = role
}

func (m *mockAuthorizationRepository) setActiveTenantAdmins(tenantID uuid.UUID, count int) {
	m.activeAdmins[tenantID] = count
}

func (m *mockAuthorizationRepository) HasPlatformPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused: i/o timeout")
	}
	if m.platformPerms[userID] != nil && m.platformPerms[userID][permission] {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthorizationRepository) HasTenantPermission(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused: i/o timeout")
	}
	if m.tenantPerms[userID] != nil && m.tenantPerms[userID][tenantID] != nil && m.tenantPerms[userID][tenantID][permission] {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthorizationRepository) UserBelongsToTenant(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused: i/o timeout")
	}
	if m.tenantPerms[userID] != nil && m.tenantPerms[userID][tenantID] != nil {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthorizationRepository) GetTenantRole(ctx context.Context, userID, tenantID uuid.UUID) (*model.Role, error) {
	if m.forceError {
		return nil, errors.New("database connection refused: i/o timeout")
	}
	if m.tenantRoles != nil && m.tenantRoles[userID] != nil && m.tenantRoles[userID][tenantID] != nil {
		return m.tenantRoles[userID][tenantID], nil
	}
	return &model.Role{
		Name:  "TENANT_ADMIN_RW",
		Scope: model.RoleScopeSystemTenant,
	}, nil
}

func (m *mockAuthorizationRepository) CountActiveTenantAdmins(ctx context.Context, tenantID uuid.UUID) (int, error) {
	if m.forceError {
		return 0, errors.New("database connection refused: i/o timeout")
	}
	if m.activeAdmins != nil {
		if count, ok := m.activeAdmins[tenantID]; ok {
			return count, nil
		}
	}
	return 1, nil
}

func TestNewAuthorizationService_NilRepo(t *testing.T) {
	_, err := service.NewAuthorizationService(nil)
	if err == nil {
		t.Fatal("expected error when authorization repository is nil")
	}
}

func TestAuthorizationService_AuthorizePlatform(t *testing.T) {
	repo := newMockAuthorizationRepository()
	svc, err := service.NewAuthorizationService(repo)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	userID := uuid.New()
	repo.grantPlatform(userID, "user.read")

	validPrincipal := &identity.Principal{
		UserID:    userID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	malformedPrincipal := &identity.Principal{
		UserID:    uuid.Nil,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// 1. Missing principal -> ErrUnauthorized
	if err := svc.AuthorizePlatform(context.Background(), nil, "user.read"); !errors.Is(err, service.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for nil principal, got: %v", err)
	}

	// 2. Malformed principal -> ErrUnauthorized
	if err := svc.AuthorizePlatform(context.Background(), malformedPrincipal, "user.read"); !errors.Is(err, service.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for malformed principal, got: %v", err)
	}

	// 3. Empty permission -> ErrForbidden
	if err := svc.AuthorizePlatform(context.Background(), validPrincipal, ""); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("expected ErrForbidden for empty permission, got: %v", err)
	}

	// 4. Granted permission -> Success (nil error)
	if err := svc.AuthorizePlatform(context.Background(), validPrincipal, "user.read"); err != nil {
		t.Errorf("expected access granted, got: %v", err)
	}

	// 5. Ungranted permission -> ErrForbidden
	if err := svc.AuthorizePlatform(context.Background(), validPrincipal, "tenant.update"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("expected ErrForbidden for ungranted permission, got: %v", err)
	}

	// 6. Database error -> Wrapped internal error
	repo.forceError = true
	if err := svc.AuthorizePlatform(context.Background(), validPrincipal, "user.read"); err == nil || errors.Is(err, service.ErrForbidden) || errors.Is(err, service.ErrUnauthorized) {
		t.Errorf("expected wrapped database error, got: %v", err)
	}
}

func TestAuthorizationService_AuthorizeTenant(t *testing.T) {
	repo := newMockAuthorizationRepository()
	svc, err := service.NewAuthorizationService(repo)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	userA := uuid.New()
	tenant1 := uuid.New()
	tenant2 := uuid.New()

	// Grant tenant1 permissions to userA
	repo.grantTenant(userA, tenant1, "tenant.read")
	repo.grantTenant(userA, tenant1, "tenant.update")

	principalA := &identity.Principal{
		UserID:    userA,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// 1. Missing principal -> ErrUnauthorized
	if err := svc.AuthorizeTenant(context.Background(), nil, tenant1, "tenant.read"); !errors.Is(err, service.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for nil principal, got: %v", err)
	}

	// 2. Nil tenant ID -> ErrForbidden
	if err := svc.AuthorizeTenant(context.Background(), principalA, uuid.Nil, "tenant.read"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("expected ErrForbidden for nil tenant ID, got: %v", err)
	}

	// 3. Authorized tenant access -> Success
	if err := svc.AuthorizeTenant(context.Background(), principalA, tenant1, "tenant.read"); err != nil {
		t.Errorf("expected access granted for assigned tenant, got: %v", err)
	}

	// 4. Cross-tenant access attempt: UserA attempts to access tenant2 -> ErrForbidden
	if err := svc.AuthorizeTenant(context.Background(), principalA, tenant2, "tenant.read"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("expected ErrForbidden for cross-tenant access attempt, got: %v", err)
	}

	// 5. Missing permission in assigned tenant -> ErrForbidden
	if err := svc.AuthorizeTenant(context.Background(), principalA, tenant1, "workflow.delete"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("expected ErrForbidden for ungranted permission in assigned tenant, got: %v", err)
	}

	// 6. Platform Admin does NOT implicitly bypass tenant boundary
	platformAdmin := uuid.New()
	repo.grantPlatform(platformAdmin, "tenant.read")
	repo.grantPlatform(platformAdmin, "tenant.update")
	principalAdmin := &identity.Principal{
		UserID:    platformAdmin,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	if err := svc.AuthorizeTenant(context.Background(), principalAdmin, tenant1, "tenant.read"); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("expected ErrForbidden: PLATFORM_ADMIN must not implicitly bypass tenant role assignment, got: %v", err)
	}

	// 7. Database error -> Wrapped internal error
	repo.forceError = true
	if err := svc.AuthorizeTenant(context.Background(), principalA, tenant1, "tenant.read"); err == nil || errors.Is(err, service.ErrForbidden) || errors.Is(err, service.ErrUnauthorized) {
		t.Errorf("expected wrapped database error, got: %v", err)
	}
}

func TestAuthorizationService_AuthorizeUserRead(t *testing.T) {
	repo := newMockAuthorizationRepository()
	svc, err := service.NewAuthorizationService(repo)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	alice := uuid.New()
	bob := uuid.New()
	admin := uuid.New()
	tenantAdmin := uuid.New()
	tenant1 := uuid.New()

	// Grant platform user.read to admin
	repo.grantPlatform(admin, "user.read")

	// Grant tenant-scoped user.read to tenantAdmin in tenant1
	repo.grantTenant(tenantAdmin, tenant1, "user.read")

	principalAlice := &identity.Principal{
		UserID:    alice,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	principalAdmin := &identity.Principal{
		UserID:    admin,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	principalTenantAdmin := &identity.Principal{
		UserID:    tenantAdmin,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// 1. Missing principal -> ErrUnauthorized
	if err := svc.AuthorizeUserRead(context.Background(), nil, alice); !errors.Is(err, service.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized for nil principal, got: %v", err)
	}

	// 2. Self-lookup (Alice reads Alice) -> Success (nil error)
	if err := svc.AuthorizeUserRead(context.Background(), principalAlice, alice); err != nil {
		t.Errorf("expected self-lookup to succeed, got: %v", err)
	}

	// 3. Platform Admin reads other user (Admin reads Alice) -> Success
	if err := svc.AuthorizeUserRead(context.Background(), principalAdmin, alice); err != nil {
		t.Errorf("expected platform-authorized lookup to succeed, got: %v", err)
	}

	// 4. Regular user reads other user (Alice reads Bob) -> ErrForbidden
	if err := svc.AuthorizeUserRead(context.Background(), principalAlice, bob); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("expected ErrForbidden for unauthorized lookup of another user, got: %v", err)
	}

	// 5. Tenant-scoped user.read CANNOT authorize platform-wide user lookup
	if err := svc.AuthorizeUserRead(context.Background(), principalTenantAdmin, bob); !errors.Is(err, service.ErrForbidden) {
		t.Errorf("expected ErrForbidden: tenant-scoped user.read must not authorize platform-wide user lookup, got: %v", err)
	}

	// 6. Database error on lookup of another user -> Wrapped internal error
	repo.forceError = true
	if err := svc.AuthorizeUserRead(context.Background(), principalAdmin, bob); err == nil || errors.Is(err, service.ErrForbidden) || errors.Is(err, service.ErrUnauthorized) {
		t.Errorf("expected wrapped database error, got: %v", err)
	}
}
