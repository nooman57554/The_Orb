package handler_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/orb_libs/identity/httpauth"
	"github.com/nooman57554/The_Orb/orb_libs/identity/jwtverify"
	"github.com/nooman57554/The_Orb/services/iam/auth"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockUserRepository struct {
	mu           sync.RWMutex
	usersByID    map[uuid.UUID]*model.User
	usersByEmail map[string]*model.User
}

func newMockUserRepository() *mockUserRepository {
	return &mockUserRepository{
		usersByID:    make(map[uuid.UUID]*model.User),
		usersByEmail: make(map[string]*model.User),
	}
}

func (m *mockUserRepository) Create(ctx context.Context, user *model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.usersByEmail[user.Email]; exists {
		return repository.ErrDuplicateEmail
	}

	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	m.usersByID[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *mockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.usersByID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return u, nil
}

func (m *mockUserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.usersByEmail[email]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return u, nil
}

func (m *mockUserRepository) Update(ctx context.Context, user *model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.usersByID[user.ID]; !ok {
		return repository.ErrNotFound
	}
	user.UpdatedAt = time.Now()
	m.usersByID[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

func (m *mockUserRepository) CreateWithTenantRole(ctx context.Context, user *model.User, tenantID, roleID uuid.UUID) error {
	return m.Create(ctx, user)
}

func (m *mockUserRepository) GetByIDInTenant(ctx context.Context, userID, tenantID uuid.UUID) (*model.TenantMemberRecord, error) {
	u, err := m.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &model.TenantMemberRecord{
		UserID:    u.ID,
		Email:     u.Email,
		Status:    u.Status,
		RoleID:    uuid.New(),
		RoleName:  "TENANT_USER",
		RoleScope: model.RoleScopeSystemTenant,
		JoinedAt:  u.CreatedAt,
	}, nil
}

func (m *mockUserRepository) ListByTenant(ctx context.Context, tenantID uuid.UUID, offset, limit int) ([]model.TenantMemberRecord, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var records []model.TenantMemberRecord
	for _, u := range m.usersByID {
		records = append(records, model.TenantMemberRecord{
			UserID:    u.ID,
			Email:     u.Email,
			Status:    u.Status,
			RoleID:    uuid.New(),
			RoleName:  "TENANT_USER",
			RoleScope: model.RoleScopeSystemTenant,
			JoinedAt:  u.CreatedAt,
		})
	}
	return records, len(records), nil
}

func (m *mockUserRepository) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.usersByID[id]
	if !ok {
		return repository.ErrNotFound
	}
	u.Status = status
	return nil
}

type mockSessionChecker struct {
	mu             sync.RWMutex
	activeSessions map[uuid.UUID]bool
	sessionUsers   map[uuid.UUID]uuid.UUID
	userRepo       *mockUserRepository
}

func (m *mockSessionChecker) IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if sessionID == uuid.Nil {
		return false, nil
	}
	if active, ok := m.activeSessions[sessionID]; ok && !active {
		return false, nil
	}
	if uid, ok := m.sessionUsers[sessionID]; ok && m.userRepo != nil {
		u, err := m.userRepo.GetByID(ctx, uid)
		if err != nil || u.Status != "active" {
			return false, nil
		}
	}
	return m.activeSessions[sessionID], nil
}

type mockAuthzRepository struct {
	platformPerms map[uuid.UUID]map[string]bool
	tenantPerms   map[uuid.UUID]map[uuid.UUID]map[string]bool
	tenantRoles   map[uuid.UUID]map[uuid.UUID]*model.Role
	activeAdmins  map[uuid.UUID]int
	forceError    bool
}

func newMockAuthzRepository() *mockAuthzRepository {
	return &mockAuthzRepository{
		platformPerms: make(map[uuid.UUID]map[string]bool),
		tenantPerms:   make(map[uuid.UUID]map[uuid.UUID]map[string]bool),
		tenantRoles:   make(map[uuid.UUID]map[uuid.UUID]*model.Role),
		activeAdmins:  make(map[uuid.UUID]int),
	}
}

func (m *mockAuthzRepository) grantPlatform(userID uuid.UUID, permission string) {
	if m.platformPerms[userID] == nil {
		m.platformPerms[userID] = make(map[string]bool)
	}
	m.platformPerms[userID][permission] = true
}

func (m *mockAuthzRepository) grantTenant(userID, tenantID uuid.UUID, permission string) {
	if m.tenantPerms[userID] == nil {
		m.tenantPerms[userID] = make(map[uuid.UUID]map[string]bool)
	}
	if m.tenantPerms[userID][tenantID] == nil {
		m.tenantPerms[userID][tenantID] = make(map[string]bool)
	}
	m.tenantPerms[userID][tenantID][permission] = true
}

func (m *mockAuthzRepository) HasPlatformPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused: i/o timeout")
	}
	if m.platformPerms[userID] != nil && m.platformPerms[userID][permission] {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthzRepository) HasTenantPermission(ctx context.Context, userID, tenantID uuid.UUID, permission string) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused: i/o timeout")
	}
	if m.tenantPerms[userID] != nil && m.tenantPerms[userID][tenantID] != nil && m.tenantPerms[userID][tenantID][permission] {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthzRepository) UserBelongsToTenant(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused: i/o timeout")
	}
	if m.tenantPerms[userID] != nil && m.tenantPerms[userID][tenantID] != nil {
		return true, nil
	}
	return false, nil
}

func (m *mockAuthzRepository) GetTenantRole(ctx context.Context, userID, tenantID uuid.UUID) (*model.Role, error) {
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

func (m *mockAuthzRepository) CountActiveTenantAdmins(ctx context.Context, tenantID uuid.UUID) (int, error) {
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

func (m *mockAuthzRepository) IsUserActive(ctx context.Context, userID uuid.UUID) (bool, error) {
	if m.forceError {
		return false, errors.New("database connection refused: i/o timeout")
	}
	return true, nil
}

type handlerFixture struct {
	userRepo         *mockUserRepository
	authzRepo        *mockAuthzRepository
	userService      *service.UserService
	authzService     *service.AuthorizationService
	userHandler      *handler.UserHandler
	jwtManager       *auth.JWTManager
	sessionChecker   *mockSessionChecker
	bearerMiddleware *httpauth.BearerMiddleware
}

func setupHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()

	userRepo := newMockUserRepository()
	authzRepo := newMockAuthzRepository()
	userService := service.NewUserService(userRepo)
	authzService, err := service.NewAuthorizationService(authzRepo)
	if err != nil {
		t.Fatalf("create authorization service: %v", err)
	}
	userHandler := handler.NewUserHandler(userService, authzService)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	keyID := "key-1"
	jwtManager, err := auth.NewJWTManager(
		priv,
		keyID,
		"orb-iam",
		"orb-platform",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create JWT manager: %v", err)
	}

	verifier, err := jwtverify.NewVerifier(
		map[string]ed25519.PublicKey{keyID: pub},
		"orb-iam",
		"orb-platform",
	)
	if err != nil {
		t.Fatalf("create principal verifier: %v", err)
	}

	sessionChecker := &mockSessionChecker{
		activeSessions: make(map[uuid.UUID]bool),
		sessionUsers:   make(map[uuid.UUID]uuid.UUID),
		userRepo:       userRepo,
	}

	bearerMiddleware, err := httpauth.NewBearerMiddleware(verifier, sessionChecker)
	if err != nil {
		t.Fatalf("create bearer middleware: %v", err)
	}

	return &handlerFixture{
		userRepo:         userRepo,
		authzRepo:        authzRepo,
		userService:      userService,
		authzService:     authzService,
		userHandler:      userHandler,
		jwtManager:       jwtManager,
		sessionChecker:   sessionChecker,
		bearerMiddleware: bearerMiddleware,
	}
}

func TestUserHandler_GetUser_NoToken(t *testing.T) {
	f := setupHandlerFixture(t)

	userID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userID.String(), nil)
	req.SetPathValue("id", userID.String())
	rec := httptest.NewRecorder()

	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	var prob struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if prob.Type != "https://orb.example.com/problems/unauthorized" {
		t.Errorf("expected unauthorized problem type, got %s", prob.Type)
	}
	if prob.Status != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, prob.Status)
	}
}

func TestUserHandler_GetUser_SelfLookup_Success(t *testing.T) {
	f := setupHandlerFixture(t)

	userID := uuid.New()
	sessionID := uuid.New()
	user := &model.User{
		ID:           userID,
		Email:        "alice@example.com",
		PasswordHash: "hashed-pass",
		Status:       "active",
		CreatedAt:    time.Now().Add(-1 * time.Hour),
		UpdatedAt:    time.Now().Add(-1 * time.Hour),
	}
	_ = f.userRepo.Create(context.Background(), user)

	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userID.String(), nil)
	req.SetPathValue("id", userID.String())

	// Attach principal for self
	principal := &identity.Principal{
		UserID:    userID,
		SessionID: sessionID,
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d. Body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp struct {
		ID     string `json:"id"`
		Email  string `json:"email"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ID != userID.String() {
		t.Errorf("expected user ID %s, got %s", userID.String(), resp.ID)
	}
	if resp.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", resp.Email)
	}
}

func TestUserHandler_GetUser_OtherUserLookup_Forbidden(t *testing.T) {
	f := setupHandlerFixture(t)

	userA := &model.User{
		ID:     uuid.New(),
		Email:  "alice@example.com",
		Status: "active",
	}
	userB := &model.User{
		ID:     uuid.New(),
		Email:  "bob@example.com",
		Status: "active",
	}
	_ = f.userRepo.Create(context.Background(), userA)
	_ = f.userRepo.Create(context.Background(), userB)

	// User A requests User B's record
	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userB.ID.String(), nil)
	req.SetPathValue("id", userB.ID.String())

	principal := &identity.Principal{
		UserID:    userA.ID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d. Body: %s", http.StatusForbidden, rec.Code, rec.Body.String())
	}

	var prob struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if prob.Type != "https://orb.example.com/problems/forbidden" {
		t.Errorf("expected forbidden problem type, got %s", prob.Type)
	}
}

func TestUserHandler_GetUser_InvalidPathUUID_BadRequest(t *testing.T) {
	f := setupHandlerFixture(t)

	userID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/users/not-a-valid-uuid", nil)
	req.SetPathValue("id", "not-a-valid-uuid")

	principal := &identity.Principal{
		UserID:    userID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d. Body: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}

	var prob struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if prob.Type != "https://orb.example.com/problems/invalid-request" {
		t.Errorf("expected invalid-request problem type, got %s", prob.Type)
	}
}

func TestUserHandler_GetUser_NonExistentUser_NotFound(t *testing.T) {
	f := setupHandlerFixture(t)

	nonExistentID := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+nonExistentID.String(), nil)
	req.SetPathValue("id", nonExistentID.String())

	// Authenticated self-lookup for a user that does not exist in repo
	principal := &identity.Principal{
		UserID:    nonExistentID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d. Body: %s", http.StatusNotFound, rec.Code, rec.Body.String())
	}

	var prob struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if prob.Type != "https://orb.example.com/problems/user-not-found" {
		t.Errorf("expected user-not-found problem type, got %s", prob.Type)
	}
}

func TestUserHandler_GetUser_SpoofedHeaderIgnored(t *testing.T) {
	f := setupHandlerFixture(t)

	userA := &model.User{ID: uuid.New(), Email: "alice@example.com", Status: "active"}
	userB := &model.User{ID: uuid.New(), Email: "bob@example.com", Status: "active"}
	_ = f.userRepo.Create(context.Background(), userA)
	_ = f.userRepo.Create(context.Background(), userB)

	// User A tries to retrieve User B using spoofed header
	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userB.ID.String(), nil)
	req.SetPathValue("id", userB.ID.String())
	req.Header.Set("X-User-ID", userB.ID.String())

	principal := &identity.Principal{
		UserID:    userA.ID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d. Header spoofing was not blocked!", http.StatusForbidden, rec.Code)
	}
}

func TestUserHandler_GetUser_PlatformAdmin_OtherUserLookup_Success(t *testing.T) {
	f := setupHandlerFixture(t)

	admin := &model.User{ID: uuid.New(), Email: "admin@example.com", Status: "active"}
	victim := &model.User{ID: uuid.New(), Email: "victim@example.com", Status: "active"}
	_ = f.userRepo.Create(context.Background(), admin)
	_ = f.userRepo.Create(context.Background(), victim)

	// Grant platform-scoped user.read to admin
	f.authzRepo.grantPlatform(admin.ID, "user.read")

	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+victim.ID.String(), nil)
	req.SetPathValue("id", victim.ID.String())

	principal := &identity.Principal{
		UserID:    admin.ID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for platform admin reading another user, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID != victim.ID.String() {
		t.Errorf("expected victim ID %s, got %s", victim.ID.String(), resp.ID)
	}
}

func TestUserHandler_GetUser_TenantAdmin_OtherUserLookup_Forbidden(t *testing.T) {
	f := setupHandlerFixture(t)

	tenantAdmin := &model.User{ID: uuid.New(), Email: "tadmin@example.com", Status: "active"}
	otherUser := &model.User{ID: uuid.New(), Email: "other@example.com", Status: "active"}
	_ = f.userRepo.Create(context.Background(), tenantAdmin)
	_ = f.userRepo.Create(context.Background(), otherUser)

	// Grant tenant-scoped user.read to tenantAdmin in tenant1
	tenant1 := uuid.New()
	f.authzRepo.grantTenant(tenantAdmin.ID, tenant1, "user.read")

	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+otherUser.ID.String(), nil)
	req.SetPathValue("id", otherUser.ID.String())

	principal := &identity.Principal{
		UserID:    tenantAdmin.ID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	// CRITICAL RULE: Tenant-scoped user.read must NOT grant platform-wide user lookup!
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden: tenant-scoped user.read must not authorize platform-wide user lookup, got %d", rec.Code)
	}
}

func TestUserHandler_GetUser_AuthzDBError_Returns500(t *testing.T) {
	f := setupHandlerFixture(t)

	caller := &model.User{ID: uuid.New(), Email: "caller@example.com", Status: "active"}
	target := &model.User{ID: uuid.New(), Email: "target@example.com", Status: "active"}
	_ = f.userRepo.Create(context.Background(), caller)
	_ = f.userRepo.Create(context.Background(), target)

	f.authzRepo.forceError = true

	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+target.ID.String(), nil)
	req.SetPathValue("id", target.ID.String())

	principal := &identity.Principal{
		UserID:    caller.ID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), principal)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error on database error, got %d: %s", rec.Code, rec.Body.String())
	}

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem: %v", err)
	}
	if prob.Detail == "database connection refused: i/o timeout" {
		t.Error("internal database error message leaked to client")
	}
}

func TestFullRoute_ServeMux_Integration(t *testing.T) {
	f := setupHandlerFixture(t)

	f.bearerMiddleware.AllowPublic("POST", "/v1/users")

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/users", f.userHandler.CreateUser)
	mux.HandleFunc("GET /v1/users/{id}", f.userHandler.GetUser)

	appHandler := f.bearerMiddleware.Require(mux)

	userA := &model.User{ID: uuid.New(), Email: "user_a@example.com", Status: "active"}
	userB := &model.User{ID: uuid.New(), Email: "user_b@example.com", Status: "active"}
	_ = f.userRepo.Create(context.Background(), userA)
	_ = f.userRepo.Create(context.Background(), userB)

	sessionA := uuid.New()
	f.sessionChecker.activeSessions[sessionA] = true

	tokenA, err := f.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    userA.ID,
		SessionID: sessionA,
		TokenID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("create token A: %v", err)
	}

	// 1. Unauthenticated GET /v1/users/{id} -> 401
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userA.ID.String(), nil)
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated request expected 401, got %d", rec.Code)
		}
	}

	// 2. Authenticated self GET /v1/users/{userA.ID} -> 200
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userA.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("authenticated self lookup expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 3. Authenticated other user GET /v1/users/{userB.ID} -> 403
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userB.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("cross-user lookup expected 403, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 4. Authenticated with revoked session -> 401
	{
		sessionRevoked := uuid.New()
		f.sessionChecker.activeSessions[sessionRevoked] = false // Revoked
		tokenRevoked, _ := f.jwtManager.CreateAccessToken(auth.Claims{
			UserID:    userA.ID,
			SessionID: sessionRevoked,
			TokenID:   uuid.New(),
		})

		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userA.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+tokenRevoked)
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("revoked session expected 401, got %d", rec.Code)
		}
	}

	// 5. POST /v1/users registration remains public without requiring token
	{
		body, _ := json.Marshal(map[string]string{
			"email":    "newuser@example.com",
			"password": "validPassword123!",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/users", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Errorf("POST /v1/users registration expected 201 without token, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 6. Unregistered or other methods not on public allowlist are protected by default -> 401
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET /v1/users expected 401, got %d", rec.Code)
		}
	}
}

func TestRegression_ProtectedEndpoint_RejectsInactiveOrSuspendedUser(t *testing.T) {
	f := setupHandlerFixture(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/users/{id}", f.userHandler.GetUser)
	appHandler := f.bearerMiddleware.Require(mux)

	user := &model.User{
		ID:        uuid.New(),
		Email:     "victim@example.com",
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	_ = f.userRepo.Create(context.Background(), user)

	sessionID := uuid.New()
	f.sessionChecker.mu.Lock()
	f.sessionChecker.activeSessions[sessionID] = true
	f.sessionChecker.sessionUsers[sessionID] = user.ID
	f.sessionChecker.mu.Unlock()

	token, err := f.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    user.ID,
		SessionID: sessionID,
		TokenID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}

	// 1. While active: request succeeds
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+user.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200 for active user, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 2. Suspend user: previously valid token must immediately be rejected
	user.Status = "suspended"
	_ = f.userRepo.Update(context.Background(), user)
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+user.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 for suspended user, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 3. Deactivate user: previously valid token must also be rejected
	user.Status = "deactivated"
	_ = f.userRepo.Update(context.Background(), user)
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+user.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		appHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401 for deactivated user, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}

func TestUserHandler_CreateUser_RequestBodyLimit_1MiB(t *testing.T) {
	f := setupHandlerFixture(t)

	// Construct oversized payload (> 1 MiB)
	largeString := strings.Repeat("a", (1<<20)+512)
	body := fmt.Sprintf(`{"email":"test@example.com","password":"%s"}`, largeString)

	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(body))
	rec := httptest.NewRecorder()

	f.userHandler.CreateUser(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized payload, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserHandler_CreateUser_MalformedJSON(t *testing.T) {
	f := setupHandlerFixture(t)

	body := `{"email":"test@example.com","password":`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(body))
	rec := httptest.NewRecorder()

	f.userHandler.CreateUser(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed json, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserHandler_CreateUser_UnknownFields(t *testing.T) {
	f := setupHandlerFixture(t)

	body := `{"email":"test@example.com","password":"password123","role":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(body))
	rec := httptest.NewRecorder()

	f.userHandler.CreateUser(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown fields, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserHandler_CreateUser_MultipleJSONValues(t *testing.T) {
	f := setupHandlerFixture(t)

	body := `{"email":"test@example.com","password":"password123"}{"extra":"data"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(body))
	rec := httptest.NewRecorder()

	f.userHandler.CreateUser(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for multiple json values, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserHandler_CreateUser_EmailValidation(t *testing.T) {
	f := setupHandlerFixture(t)

	tests := []struct {
		name       string
		email      string
		wantStatus int
	}{
		{"empty email", "", http.StatusBadRequest},
		{"whitespace email", "   ", http.StatusBadRequest},
		{"not an email", "notanemail", http.StatusBadRequest},
		{"missing domain", "user@", http.StatusBadRequest},
		{"missing user", "@example.com", http.StatusBadRequest},
		{"dot without domain", "user@.com", http.StatusBadRequest},
		{"domain without dot", "user@localhost", http.StatusBadRequest},
		{"email with spaces", "user name@example.com", http.StatusBadRequest},
		{"valid email", "alice.smith+tag@example.com", http.StatusCreated},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]string{
				"email":    tc.email,
				"password": "validPassword123!",
			}
			b, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/v1/users", bytes.NewReader(b))
			rec := httptest.NewRecorder()

			f.userHandler.CreateUser(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("email %q: expected status %d, got %d: %s", tc.email, tc.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUserHandler_CreateUser_PasswordBounds(t *testing.T) {
	f := setupHandlerFixture(t)

	tests := []struct {
		name       string
		password   string
		wantStatus int
	}{
		{"too short (7 chars)", "1234567", http.StatusBadRequest},
		{"min length (8 chars)", "12345678", http.StatusCreated},
		{"max length (128 chars)", strings.Repeat("a", 128), http.StatusCreated},
		{"too long (129 chars)", strings.Repeat("a", 129), http.StatusBadRequest},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]string{
				"email":    fmt.Sprintf("user%d@example.com", i),
				"password": tc.password,
			}
			b, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/v1/users", bytes.NewReader(b))
			rec := httptest.NewRecorder()

			f.userHandler.CreateUser(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("password length %d: expected status %d, got %d: %s", len(tc.password), tc.wantStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUserHandler_CreateUser_ConcurrentRegistration_Conflict(t *testing.T) {
	f := setupHandlerFixture(t)

	const concurrency = 10
	var wg sync.WaitGroup
	statusCodes := make([]int, concurrency)

	targetEmail := "concurrent@example.com"
	password := "safePassword123!"

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := map[string]string{
				"email":    targetEmail,
				"password": password,
			}
			b, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/v1/users", bytes.NewReader(b))
			rec := httptest.NewRecorder()

			f.userHandler.CreateUser(rec, req)
			statusCodes[idx] = rec.Code
		}(i)
	}

	wg.Wait()

	var createdCount int
	var conflictCount int
	for _, code := range statusCodes {
		switch code {
		case http.StatusCreated:
			createdCount++
		case http.StatusConflict:
			conflictCount++
		default:
			t.Errorf("unexpected status code during concurrent registration: %d", code)
		}
	}

	if createdCount != 1 {
		t.Errorf("expected exactly 1 registration to succeed, got %d", createdCount)
	}
	if conflictCount != concurrency-1 {
		t.Errorf("expected %d conflict responses, got %d", concurrency-1, conflictCount)
	}
}
