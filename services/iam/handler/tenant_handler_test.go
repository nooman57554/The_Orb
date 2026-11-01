package handler_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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

type mockTenantRepository struct {
	mu          sync.RWMutex
	tenantsByID map[uuid.UUID]*model.Tenant
	forceGetErr bool
	forceUpdErr bool
}

func newMockTenantRepository() *mockTenantRepository {
	return &mockTenantRepository{
		tenantsByID: make(map[uuid.UUID]*model.Tenant),
	}
}

func (m *mockTenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.forceGetErr {
		return nil, errors.New("database connection refused: i/o timeout")
	}

	t, ok := m.tenantsByID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copy := *t
	return &copy, nil
}

func (m *mockTenantRepository) Update(ctx context.Context, tenant *model.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.forceUpdErr {
		return errors.New("database connection refused: i/o timeout")
	}

	if _, ok := m.tenantsByID[tenant.ID]; !ok {
		return repository.ErrNotFound
	}

	copy := *tenant
	copy.UpdatedAt = time.Now()
	m.tenantsByID[tenant.ID] = &copy
	return nil
}

func (m *mockTenantRepository) Create(ctx context.Context, tenant *model.Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if tenant.ID == uuid.Nil {
		tenant.ID = uuid.New()
	}
	now := time.Now()
	tenant.CreatedAt = now
	tenant.UpdatedAt = now
	copy := *tenant
	m.tenantsByID[tenant.ID] = &copy
	return nil
}

func (m *mockTenantRepository) GetBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, t := range m.tenantsByID {
		if t.Slug == slug {
			copy := *t
			return &copy, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (m *mockTenantRepository) List(ctx context.Context, offset, limit int) ([]model.Tenant, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tenants []model.Tenant
	for _, t := range m.tenantsByID {
		tenants = append(tenants, *t)
	}
	return tenants, len(tenants), nil
}

func (m *mockTenantRepository) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	t, ok := m.tenantsByID[id]
	if !ok {
		return repository.ErrNotFound
	}
	t.Status = status
	return nil
}

type tenantFixture struct {
	tenantRepo       *mockTenantRepository
	authzRepo        *mockAuthzRepository
	authzService     *service.AuthorizationService
	tenantHandler    *handler.TenantHandler
	jwtManager       *auth.JWTManager
	sessionChecker   *mockSessionChecker
	bearerMiddleware *httpauth.BearerMiddleware
	appHandler       http.Handler
}

func setupTenantFixture(t *testing.T) *tenantFixture {
	t.Helper()

	tenantRepo := newMockTenantRepository()
	authzRepo := newMockAuthzRepository()
	authzService, err := service.NewAuthorizationService(authzRepo)
	if err != nil {
		t.Fatalf("create authorization service: %v", err)
	}

	tenantHandler := handler.NewTenantHandler(tenantRepo, authzService)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	keyID := "key-tenant-1"
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
	}

	bearerMiddleware, err := httpauth.NewBearerMiddleware(
		verifier,
		sessionChecker,
		"POST /v1/auth/login",
		"POST /v1/auth/refresh",
		"POST /v1/users",
	)
	if err != nil {
		t.Fatalf("create bearer middleware: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/tenants/{id}", tenantHandler.GetTenant)
	mux.HandleFunc("PATCH /v1/tenants/{id}", tenantHandler.UpdateTenant)

	appHandler := bearerMiddleware.Require(mux)

	return &tenantFixture{
		tenantRepo:       tenantRepo,
		authzRepo:        authzRepo,
		authzService:     authzService,
		tenantHandler:    tenantHandler,
		jwtManager:       jwtManager,
		sessionChecker:   sessionChecker,
		bearerMiddleware: bearerMiddleware,
		appHandler:       appHandler,
	}
}

func (f *tenantFixture) createToken(t *testing.T, userID uuid.UUID) string {
	t.Helper()
	sessionID := uuid.New()
	f.sessionChecker.activeSessions[sessionID] = true
	f.sessionChecker.sessionUsers[sessionID] = userID

	token, err := f.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    userID,
		SessionID: sessionID,
	})
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}
	return token
}

// -----------------------------------------------------------------------------
// Tenant Read Tests (GET /v1/tenants/{id})
// -----------------------------------------------------------------------------

func TestTenantHandler_GetTenant_TenantAdmin_Success(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenantID := uuid.New()

	tenant := &model.Tenant{
		ID:        tenantID,
		Name:      "Acme Corp",
		Slug:      "acme",
		Status:    "active",
		CreatedAt: time.Now().Add(-1 * time.Hour),
		UpdatedAt: time.Now().Add(-1 * time.Hour),
	}
	f.tenantRepo.tenantsByID[tenantID] = tenant

	// Grant tenant-scoped tenant.read to userID in tenantID
	f.authzRepo.grantTenant(userID, tenantID, "tenant.read")

	token := f.createToken(t, userID)

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenantID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ID != tenantID.String() || resp.Name != "Acme Corp" || resp.Slug != "acme" {
		t.Errorf("unexpected tenant response: %+v", resp)
	}
}

func TestTenantHandler_GetTenant_CrossTenant_Forbidden(t *testing.T) {
	f := setupTenantFixture(t)

	userA := uuid.New()
	tenant1 := uuid.New()
	tenant2 := uuid.New()

	f.tenantRepo.tenantsByID[tenant1] = &model.Tenant{ID: tenant1, Name: "Tenant 1", Slug: "t1", Status: "active"}
	f.tenantRepo.tenantsByID[tenant2] = &model.Tenant{ID: tenant2, Name: "Tenant 2", Slug: "t2", Status: "active"}

	// UserA is TENANT_ADMIN_RW in tenant1, but NOT in tenant2
	f.authzRepo.grantTenant(userA, tenant1, "tenant.read")
	f.authzRepo.grantTenant(userA, tenant1, "tenant.update")

	token := f.createToken(t, userA)

	// UserA attempts cross-tenant access to tenant2
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenant2.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	// MUST be 403 Forbidden! Client-selected tenant ID must never cross boundaries
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on cross-tenant access, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTenantHandler_GetTenant_PlatformAdminWithoutTenantAssignment_Forbidden(t *testing.T) {
	f := setupTenantFixture(t)

	platformAdmin := uuid.New()
	tenant1 := uuid.New()

	f.tenantRepo.tenantsByID[tenant1] = &model.Tenant{ID: tenant1, Name: "Tenant 1", Slug: "t1", Status: "active"}

	// Platform admin has platform-scoped tenant.read, but NO tenant_role_assignment in tenant1
	f.authzRepo.grantPlatform(platformAdmin, "tenant.read")

	token := f.createToken(t, platformAdmin)

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenant1.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	// CRITICAL RULE: PLATFORM_ADMIN does not implicitly bypass tenant assignment requirements!
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden: platform admin without tenant role assignment must be rejected, got %d", rec.Code)
	}
}

func TestTenantHandler_GetTenant_MissingPermission_Forbidden(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenant1 := uuid.New()

	f.tenantRepo.tenantsByID[tenant1] = &model.Tenant{ID: tenant1, Name: "Tenant 1", Slug: "t1", Status: "active"}

	// User is in tenant1, but only has "workflow.execute" (lacks "tenant.read")
	f.authzRepo.grantTenant(userID, tenant1, "workflow.execute")

	token := f.createToken(t, userID)

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenant1.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for missing permission, got %d", rec.Code)
	}
}

func TestTenantHandler_GetTenant_Unauthenticated_Unauthorized(t *testing.T) {
	f := setupTenantFixture(t)

	tenant1 := uuid.New()

	// Missing Authorization header
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenant1.String(), nil)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unauthenticated request, got %d", rec.Code)
	}
}

func TestTenantHandler_GetTenant_MalformedPrincipal_Unauthorized(t *testing.T) {
	f := setupTenantFixture(t)

	tenant1 := uuid.New()

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenant1.String(), nil)
	req.SetPathValue("id", tenant1.String())

	// Attach malformed principal
	malformed := &identity.Principal{
		UserID:    uuid.Nil,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := identity.WithPrincipal(req.Context(), malformed)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.tenantHandler.GetTenant(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for malformed principal, got %d", rec.Code)
	}
}

func TestTenantHandler_GetTenant_InvalidUUID_BadRequest(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	token := f.createToken(t, userID)

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/not-a-uuid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid UUID, got %d", rec.Code)
	}
}

func TestTenantHandler_GetTenant_NotFound_404(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenant1 := uuid.New()

	// Authorized for tenant1, but tenant does not exist in repo
	f.authzRepo.grantTenant(userID, tenant1, "tenant.read")
	token := f.createToken(t, userID)

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenant1.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rec.Code)
	}
}

func TestTenantHandler_GetTenant_AuthzDBError_Returns500(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenant1 := uuid.New()
	token := f.createToken(t, userID)

	f.authzRepo.forceError = true

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenant1.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error, got %d: %s", rec.Code, rec.Body.String())
	}

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem details: %v", err)
	}
	if prob.Detail == "database connection refused: i/o timeout" {
		t.Error("internal database error message leaked to client")
	}
}

func TestTenantHandler_GetTenant_RepoDBError_Returns500(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenant1 := uuid.New()

	f.authzRepo.grantTenant(userID, tenant1, "tenant.read")
	f.tenantRepo.forceGetErr = true
	token := f.createToken(t, userID)

	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+tenant1.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error on repo failure, got %d", rec.Code)
	}

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem details: %v", err)
	}
	if prob.Detail == "database connection refused: i/o timeout" {
		t.Error("internal database error message leaked to client")
	}
}

// -----------------------------------------------------------------------------
// Tenant Update Tests (PATCH /v1/tenants/{id})
// -----------------------------------------------------------------------------

func TestTenantHandler_UpdateTenant_TenantAdmin_Success(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenantID := uuid.New()

	tenant := &model.Tenant{
		ID:        tenantID,
		Name:      "Original Name",
		Slug:      "orig",
		Status:    "active",
		CreatedAt: time.Now().Add(-1 * time.Hour),
		UpdatedAt: time.Now().Add(-1 * time.Hour),
	}
	f.tenantRepo.tenantsByID[tenantID] = tenant

	// Grant tenant-scoped tenant.update to userID in tenantID
	f.authzRepo.grantTenant(userID, tenantID, "tenant.update")

	token := f.createToken(t, userID)

	body, _ := json.Marshal(map[string]string{"name": "Renamed Tenant"})
	req := httptest.NewRequest(http.MethodPatch, "/v1/tenants/"+tenantID.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on update, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Name != "Renamed Tenant" {
		t.Errorf("expected updated name 'Renamed Tenant', got %q", resp.Name)
	}

	// Verify persistence in repository
	if f.tenantRepo.tenantsByID[tenantID].Name != "Renamed Tenant" {
		t.Errorf("repository was not updated")
	}
}

func TestTenantHandler_UpdateTenant_CrossTenant_Forbidden(t *testing.T) {
	f := setupTenantFixture(t)

	userA := uuid.New()
	tenant1 := uuid.New()
	tenant2 := uuid.New()

	f.tenantRepo.tenantsByID[tenant1] = &model.Tenant{ID: tenant1, Name: "Tenant 1", Slug: "t1", Status: "active"}
	f.tenantRepo.tenantsByID[tenant2] = &model.Tenant{ID: tenant2, Name: "Tenant 2", Slug: "t2", Status: "active"}

	// UserA is admin only in tenant1
	f.authzRepo.grantTenant(userA, tenant1, "tenant.update")

	token := f.createToken(t, userA)

	body, _ := json.Marshal(map[string]string{"name": "Attacker Name"})
	req := httptest.NewRequest(http.MethodPatch, "/v1/tenants/"+tenant2.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant update attempt, got %d", rec.Code)
	}
}

func TestTenantHandler_UpdateTenant_ReadOnlyRole_Forbidden(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenant1 := uuid.New()

	f.tenantRepo.tenantsByID[tenant1] = &model.Tenant{ID: tenant1, Name: "Tenant 1", Slug: "t1", Status: "active"}

	// User has tenant.read but LACKS tenant.update (e.g. TENANT_ADMIN_READONLY)
	f.authzRepo.grantTenant(userID, tenant1, "tenant.read")

	token := f.createToken(t, userID)

	body, _ := json.Marshal(map[string]string{"name": "Readonly Update Attempt"})
	req := httptest.NewRequest(http.MethodPatch, "/v1/tenants/"+tenant1.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for read-only user attempting update, got %d", rec.Code)
	}
}

func TestTenantHandler_UpdateTenant_InvalidJSON_BadRequest(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenant1 := uuid.New()
	f.tenantRepo.tenantsByID[tenant1] = &model.Tenant{ID: tenant1, Name: "Tenant 1", Slug: "t1", Status: "active"}
	f.authzRepo.grantTenant(userID, tenant1, "tenant.update")
	token := f.createToken(t, userID)

	req := httptest.NewRequest(http.MethodPatch, "/v1/tenants/"+tenant1.String(), bytes.NewReader([]byte("{invalid-json")))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid JSON, got %d", rec.Code)
	}
}

func TestTenantHandler_UpdateTenant_EmptyName_BadRequest(t *testing.T) {
	f := setupTenantFixture(t)

	userID := uuid.New()
	tenant1 := uuid.New()
	f.tenantRepo.tenantsByID[tenant1] = &model.Tenant{ID: tenant1, Name: "Tenant 1", Slug: "t1", Status: "active"}
	f.authzRepo.grantTenant(userID, tenant1, "tenant.update")
	token := f.createToken(t, userID)

	body, _ := json.Marshal(map[string]string{"name": "   "})
	req := httptest.NewRequest(http.MethodPatch, "/v1/tenants/"+tenant1.String(), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for empty name, got %d", rec.Code)
	}
}
