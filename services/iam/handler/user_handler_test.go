package handler_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/auth"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/middleware"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockUserRepository struct {
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
	u, ok := m.usersByID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return u, nil
}

func (m *mockUserRepository) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	u, ok := m.usersByEmail[email]
	if !ok {
		return nil, repository.ErrNotFound
	}
	return u, nil
}

func (m *mockUserRepository) Update(ctx context.Context, user *model.User) error {
	if _, ok := m.usersByID[user.ID]; !ok {
		return repository.ErrNotFound
	}
	user.UpdatedAt = time.Now()
	m.usersByID[user.ID] = user
	m.usersByEmail[user.Email] = user
	return nil
}

type mockSessionChecker struct {
	activeSessions map[uuid.UUID]bool
}

func (m *mockSessionChecker) IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	return m.activeSessions[sessionID], nil
}

type handlerFixture struct {
	userRepo       *mockUserRepository
	userService    *service.UserService
	userHandler    *handler.UserHandler
	jwtManager     *auth.JWTManager
	sessionChecker *mockSessionChecker
	authMiddleware *middleware.AuthMiddleware
}

func setupHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()

	userRepo := newMockUserRepository()
	userService := service.NewUserService(userRepo)
	userHandler := handler.NewUserHandler(userService)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	keyID := "key-1"
	jwtManager, err := auth.NewJWTManager(
		priv,
		keyID,
		map[string]ed25519.PublicKey{keyID: pub},
		"orb-iam",
		"orb-platform",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create JWT manager: %v", err)
	}

	sessionChecker := &mockSessionChecker{
		activeSessions: make(map[uuid.UUID]bool),
	}

	authMiddleware, err := middleware.NewAuthMiddleware(jwtManager, sessionChecker)
	if err != nil {
		t.Fatalf("create auth middleware: %v", err)
	}

	return &handlerFixture{
		userRepo:       userRepo,
		userService:    userService,
		userHandler:    userHandler,
		jwtManager:     jwtManager,
		sessionChecker: sessionChecker,
		authMiddleware: authMiddleware,
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

	// Attach claims for self
	claims := &auth.Claims{
		UserID:    userID,
		SessionID: sessionID,
		TokenID:   uuid.New(),
	}
	ctx := middleware.WithClaims(req.Context(), claims)
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

	claims := &auth.Claims{
		UserID:    userA.ID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := middleware.WithClaims(req.Context(), claims)
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

	claims := &auth.Claims{
		UserID:    userID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := middleware.WithClaims(req.Context(), claims)
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
	claims := &auth.Claims{
		UserID:    nonExistentID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := middleware.WithClaims(req.Context(), claims)
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

	claims := &auth.Claims{
		UserID:    userA.ID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx := middleware.WithClaims(req.Context(), claims)
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	f.userHandler.GetUser(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d. Header spoofing was not blocked!", http.StatusForbidden, rec.Code)
	}
}

func TestFullRoute_ServeMux_Integration(t *testing.T) {
	f := setupHandlerFixture(t)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/users", f.userHandler.CreateUser)
	mux.Handle("GET /v1/users/{id}", f.authMiddleware.RequireAuth(http.HandlerFunc(f.userHandler.GetUser)))

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
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated request expected 401, got %d", rec.Code)
		}
	}

	// 2. Authenticated self GET /v1/users/{userA.ID} -> 200
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userA.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("authenticated self lookup expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 3. Authenticated other user GET /v1/users/{userB.ID} -> 403
	{
		req := httptest.NewRequest(http.MethodGet, "/v1/users/"+userB.ID.String(), nil)
		req.Header.Set("Authorization", "Bearer "+tokenA)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
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
		mux.ServeHTTP(rec, req)
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
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Errorf("POST /v1/users registration expected 201 without token, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}
