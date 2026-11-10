package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockUserRepoForHandler struct {
	mockUserRepository
	members map[uuid.UUID]map[uuid.UUID]uuid.UUID
}

func newMockUserRepoForHandler() *mockUserRepoForHandler {
	return &mockUserRepoForHandler{
		mockUserRepository: *newMockUserRepository(),
		members:            make(map[uuid.UUID]map[uuid.UUID]uuid.UUID),
	}
}

func (m *mockUserRepoForHandler) CreateWithTenantRole(ctx context.Context, user *model.User, tenantID, roleID uuid.UUID) error {
	if err := m.Create(ctx, user); err != nil {
		return err
	}
	if m.members[tenantID] == nil {
		m.members[tenantID] = make(map[uuid.UUID]uuid.UUID)
	}
	m.members[tenantID][user.ID] = roleID
	return nil
}

func (m *mockUserRepoForHandler) GetByIDInTenant(ctx context.Context, userID, tenantID uuid.UUID) (*model.TenantMemberRecord, error) {
	u, err := m.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	roleID := m.members[tenantID][userID]
	return &model.TenantMemberRecord{
		UserID:    u.ID,
		Email:     u.Email,
		Status:    u.Status,
		RoleID:    roleID,
		RoleName:  "TENANT_ADMIN_RW",
		RoleScope: model.RoleScopeSystemTenant,
		JoinedAt:  time.Now(),
	}, nil
}

func (m *mockUserRepoForHandler) ListByTenant(ctx context.Context, tenantID uuid.UUID, offset, limit int) ([]model.TenantMemberRecord, int, error) {
	var list []model.TenantMemberRecord
	for uID, rID := range m.members[tenantID] {
		u, _ := m.GetByID(ctx, uID)
		list = append(list, model.TenantMemberRecord{
			UserID:    u.ID,
			Email:     u.Email,
			Status:    u.Status,
			RoleID:    rID,
			RoleName:  "TENANT_USER",
			RoleScope: model.RoleScopeSystemTenant,
			JoinedAt:  time.Now(),
		})
	}
	return list, len(list), nil
}

func TestTenantUserHandler_ProvisionUser_Success(t *testing.T) {
	userRepo := newMockUserRepoForHandler()
	tenantRepo := newMockTenantRepository()
	roleRepo := &mockRoleRepoForHandler{roles: make(map[uuid.UUID]*model.Role)}
	roleAssignRepo := &mockRoleAssignRepoForHandler{members: make(map[uuid.UUID][]model.TenantMemberRecord)}
	authzRepo := newMockAuthzRepository()

	tenantID := uuid.New()
	tenantRepo.Create(context.Background(), &model.Tenant{ID: tenantID, Status: "active"})

	roleID := uuid.New()
	roleRepo.roles[roleID] = &model.Role{
		ID:    roleID,
		Name:  "TENANT_USER",
		Scope: model.RoleScopeSystemTenant,
	}

	roleAssignSvc, _ := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	tenantUserService, _ := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignSvc, authzRepo)

	callerID := uuid.New()
	authzRepo.grantPlatform(callerID, authorization.PermPlatformRoleAssign)
	authzRepo.grantTenant(callerID, tenantID, authorization.PermTenantUserCreate)

	h := handler.NewTenantUserHandler(tenantUserService, roleAssignSvc)

	body, _ := json.Marshal(map[string]any{
		"email":    "alice@example.com",
		"password": "StrongPassword123!",
		"role_id":  roleID.String(),
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/tenants/"+tenantID.String()+"/users", bytes.NewReader(body))
	req.SetPathValue("tenantID", tenantID.String())
	req = req.WithContext(identity.WithPrincipal(req.Context(), &identity.Principal{UserID: callerID, SessionID: uuid.New(), TokenID: uuid.New()}))
	rec := httptest.NewRecorder()

	h.ProvisionUser(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTenantUserHandler_DemoteLastAdmin_Conflict(t *testing.T) {
	userRepo := newMockUserRepoForHandler()
	tenantRepo := newMockTenantRepository()
	roleRepo := &mockRoleRepoForHandler{roles: make(map[uuid.UUID]*model.Role)}
	roleAssignRepo := &mockRoleAssignRepoForHandler{
		members: make(map[uuid.UUID][]model.TenantMemberRecord),
	}
	authzRepo := newMockAuthzRepository()

	tenantID := uuid.New()
	tenantRepo.Create(context.Background(), &model.Tenant{ID: tenantID, Status: "active"})

	adminRoleID := uuid.New()
	adminRole := &model.Role{
		ID:    adminRoleID,
		Name:  "TENANT_ADMIN_RW",
		Scope: model.RoleScopeSystemTenant,
		Permissions: []model.Permission{
			{Name: authorization.PermTenantUserAssignRole},
		},
	}
	roleRepo.roles[adminRoleID] = adminRole

	memberRoleID := uuid.New()
	memberRole := &model.Role{
		ID:    memberRoleID,
		Name:  "TENANT_USER",
		Scope: model.RoleScopeSystemTenant,
	}
	roleRepo.roles[memberRoleID] = memberRole

	adminUserID := uuid.New()
	userRepo.Create(context.Background(), &model.User{ID: adminUserID, Email: "admin@example.com", Status: "active"})

	roleAssignRepo.tenantRoles = map[uuid.UUID]map[uuid.UUID]*model.Role{
		adminUserID: {tenantID: adminRole},
	}
	roleAssignRepo.activeTenantAdmins = map[uuid.UUID]int{tenantID: 1}
	authzRepo.tenantRoles[adminUserID] = map[uuid.UUID]*model.Role{tenantID: adminRole}

	roleAssignSvc, _ := service.NewRoleAssignmentService(roleAssignRepo, roleRepo, userRepo, tenantRepo, authzRepo)
	tenantUserService, _ := service.NewTenantUserService(userRepo, tenantRepo, roleRepo, roleAssignSvc, authzRepo)

	authzRepo.grantTenant(adminUserID, tenantID, authorization.PermTenantUserAssignRole)

	h := handler.NewTenantUserHandler(tenantUserService, roleAssignSvc)

	body, _ := json.Marshal(map[string]any{
		"role_id": memberRoleID.String(),
	})

	req := httptest.NewRequest(http.MethodPatch, "/v1/tenants/"+tenantID.String()+"/users/"+adminUserID.String()+"/role", bytes.NewReader(body))
	req.SetPathValue("tenantID", tenantID.String())
	req.SetPathValue("userID", adminUserID.String())
	req = req.WithContext(identity.WithPrincipal(req.Context(), &identity.Principal{UserID: adminUserID, SessionID: uuid.New(), TokenID: uuid.New()}))
	rec := httptest.NewRecorder()

	h.ChangeRole(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("expected status 409 Conflict on demoting last admin, got %d: %s", rec.Code, rec.Body.String())
	}
}
