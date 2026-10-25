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
	"github.com/nooman57554/The_Orb/orb_libs/identity/httpauth"
	"github.com/nooman57554/The_Orb/orb_libs/identity/jwtverify"
	"github.com/nooman57554/The_Orb/services/iam/auth"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type mockSessionRepository struct {
	mu                  sync.RWMutex
	sessionsByID        map[uuid.UUID]*model.Session
	sessionsByTokenHash map[string]*model.Session
	userRepo            repository.UserRepository
}

func newMockSessionRepository(userRepo repository.UserRepository) *mockSessionRepository {
	return &mockSessionRepository{
		sessionsByID:        make(map[uuid.UUID]*model.Session),
		sessionsByTokenHash: make(map[string]*model.Session),
		userRepo:            userRepo,
	}
}

func (m *mockSessionRepository) Create(ctx context.Context, session *model.Session, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s := *session
	m.sessionsByID[s.ID] = &s
	m.sessionsByTokenHash[tokenHash] = &s
	return nil
}

func (m *mockSessionRepository) GetByRefreshTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.sessionsByTokenHash[tokenHash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	if s.RevokedAt != nil || time.Now().After(s.ExpiresAt) {
		return nil, repository.ErrNotFound
	}
	copy := *s
	return &copy, nil
}

func (m *mockSessionRepository) RotateRefreshToken(ctx context.Context, oldTokenHash, newTokenHash string) (*model.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessionsByTokenHash[oldTokenHash]
	if !ok || s.RevokedAt != nil || time.Now().After(s.ExpiresAt) {
		return nil, repository.ErrNotFound
	}

	delete(m.sessionsByTokenHash, oldTokenHash)
	m.sessionsByTokenHash[newTokenHash] = s
	copy := *s
	return &copy, nil
}

func (m *mockSessionRepository) RevokeByRefreshTokenHash(ctx context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessionsByTokenHash[tokenHash]
	if !ok {
		return repository.ErrNotFound
	}

	if s.RevokedAt == nil {
		now := time.Now()
		s.RevokedAt = &now
	}
	return nil
}

func (m *mockSessionRepository) Revoke(ctx context.Context, sessionID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessionsByID[sessionID]
	if !ok {
		return repository.ErrNotFound
	}

	if s.RevokedAt == nil {
		now := time.Now()
		s.RevokedAt = &now
	}
	return nil
}

func (m *mockSessionRepository) IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if sessionID == uuid.Nil {
		return false, nil
	}

	s, ok := m.sessionsByID[sessionID]
	if !ok || s.RevokedAt != nil || time.Now().After(s.ExpiresAt) {
		return false, nil
	}

	if m.userRepo != nil {
		u, err := m.userRepo.GetByID(ctx, s.UserID)
		if err != nil || u.Status != "active" {
			return false, nil
		}
	}

	return true, nil
}

type authTestFixture struct {
	userRepo         *mockUserRepositoryWithDBErrors
	sessionRepo      *mockSessionRepository
	authService      *service.AuthService
	authHandler      *handler.AuthHandler
	jwtManager       *auth.JWTManager
	bearerMiddleware *httpauth.BearerMiddleware
	appHandler       http.Handler
}

type mockUserRepositoryWithDBErrors struct {
	mockUserRepository
	forceDBError bool
}

func (m *mockUserRepositoryWithDBErrors) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	if m.forceDBError {
		return nil, errors.New("database connection refused: i/o timeout")
	}
	return m.mockUserRepository.GetByEmail(ctx, email)
}

func setupAuthFixture(t *testing.T) *authTestFixture {
	t.Helper()

	userRepo := &mockUserRepositoryWithDBErrors{
		mockUserRepository: *newMockUserRepository(),
	}
	sessionRepo := newMockSessionRepository(userRepo)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	keyID := "key-auth-1"
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

	authService, err := service.NewAuthService(
		userRepo,
		sessionRepo,
		jwtManager,
		15*time.Minute,
		24*time.Hour,
	)
	if err != nil {
		t.Fatalf("create auth service: %v", err)
	}

	authHandler := handler.NewAuthHandler(authService)

	verifier, err := jwtverify.NewVerifier(
		map[string]ed25519.PublicKey{keyID: pub},
		"orb-iam",
		"orb-platform",
	)
	if err != nil {
		t.Fatalf("create principal verifier: %v", err)
	}

	bearerMiddleware, err := httpauth.NewBearerMiddleware(
		verifier,
		sessionRepo,
		"POST /v1/auth/login",
		"POST /v1/auth/refresh",
		"POST /v1/auth/logout",
	)
	if err != nil {
		t.Fatalf("create bearer middleware: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/login", authHandler.Login)
	mux.HandleFunc("POST /v1/auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /v1/auth/logout", authHandler.Logout)

	appHandler := bearerMiddleware.Require(mux)

	return &authTestFixture{
		userRepo:         userRepo,
		sessionRepo:      sessionRepo,
		authService:      authService,
		authHandler:      authHandler,
		jwtManager:       jwtManager,
		bearerMiddleware: bearerMiddleware,
		appHandler:       appHandler,
	}
}

// -----------------------------------------------------------------------------
// Fix 5 Tests: Login Account-Enumeration Timing & DB Errors
// -----------------------------------------------------------------------------

func TestAuthHandler_Login_TimingAndEnumerationDefense(t *testing.T) {
	f := setupAuthFixture(t)

	// Create a real user using the UserService to generate a real Argon2id hash
	userService := service.NewUserService(f.userRepo)
	createdUser, err := userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "existing@example.com",
		Password: "correctPassword123!",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// 1. Success login
	{
		body, _ := json.Marshal(map[string]string{
			"email":    "existing@example.com",
			"password": "correctPassword123!",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 2. Wrong password on existing user -> 401
	var wrongPassBody string
	{
		body, _ := json.Marshal(map[string]string{
			"email":    "existing@example.com",
			"password": "wrongPassword!",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong password, got %d: %s", rec.Code, rec.Body.String())
		}
		wrongPassBody = rec.Body.String()
	}

	// 3. Unknown user -> 401 (must execute dummy Argon2id hash and return identical response body)
	var unknownUserBody string
	{
		body, _ := json.Marshal(map[string]string{
			"email":    "nonexistent@example.com",
			"password": "anyPassword123!",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unknown user, got %d: %s", rec.Code, rec.Body.String())
		}
		unknownUserBody = rec.Body.String()
	}

	// Assert responses are completely indistinguishable (status, title, detail)
	if wrongPassBody != unknownUserBody {
		t.Errorf("expected response for wrong password and unknown user to be identical to prevent enumeration.\nWrong pass: %s\nUnknown: %s", wrongPassBody, unknownUserBody)
	}

	// 4. Inactive user -> 401
	{
		user, _ := f.userRepo.GetByID(context.Background(), createdUser.ID)
		user.Status = "suspended"
		_ = f.userRepo.Update(context.Background(), user)

		body, _ := json.Marshal(map[string]string{
			"email":    "existing@example.com",
			"password": "correctPassword123!",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for inactive user, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 5. Database error: MUST NOT be treated as missing account or return 401
	{
		f.userRepo.forceDBError = true
		body, _ := json.Marshal(map[string]string{
			"email":    "existing@example.com",
			"password": "correctPassword123!",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 for database error, got %d: %s", rec.Code, rec.Body.String())
		}
		f.userRepo.forceDBError = false
	}
}

// -----------------------------------------------------------------------------
// Fix 2 Tests: Logout Race With Refresh, Idempotency, and Security
// -----------------------------------------------------------------------------

func TestAuthHandler_Logout_BearerToken_Success(t *testing.T) {
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "logout_user@example.com",
		Password: "password123!",
	})

	tokens, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "logout_user@example.com",
		Password: "password123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Authenticated logout via Bearer token (no body required)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d: %s", rec.Code, rec.Body.String())
	}

	// Repeated logout with the same Bearer token must be idempotent (204)
	{
		req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
		req2.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		rec2 := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec2, req2)

		if rec2.Code != http.StatusNoContent {
			t.Fatalf("expected 204 No Content for repeated logout, got %d: %s", rec2.Code, rec2.Body.String())
		}
	}
}

func TestAuthHandler_Logout_RaceWithRefresh(t *testing.T) {
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "race_user@example.com",
		Password: "password123!",
	})

	// Initial login
	tokens1, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "race_user@example.com",
		Password: "password123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Client performs a refresh: refresh token rotates from tokens1.RefreshToken to tokens2.RefreshToken
	tokens2, err := f.authService.Refresh(context.Background(), tokens1.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// Client racing: client issues logout using the previously held tokens1.AccessToken
	// Even though the refresh token hash has rotated in the database, the immutable session ID
	// in tokens1.AccessToken securely establishes the caller's session and revokes it.
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokens1.AccessToken)
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verification: the session is revoked. A subsequent refresh attempt with the new refresh token fails.
	_, err = f.authService.Refresh(context.Background(), tokens2.RefreshToken)
	if !errors.Is(err, service.ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken after logout, got %v", err)
	}
}

func TestAuthHandler_Logout_AttemptsToAffectAnotherSession(t *testing.T) {
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "user_a@example.com",
		Password: "password123!",
	})
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "user_b@example.com",
		Password: "password123!",
	})

	tokensA, _ := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "user_a@example.com",
		Password: "password123!",
	})
	tokensB, _ := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "user_b@example.com",
		Password: "password123!",
	})
	_ = tokensB

	// Find session B ID from session repo
	var sessionBID uuid.UUID
	f.sessionRepo.mu.RLock()
	for id, s := range f.sessionRepo.sessionsByID {
		if s.UserID != uuid.Nil {
			u, _ := f.userRepo.GetByID(context.Background(), s.UserID)
			if u != nil && u.Email == "user_b@example.com" {
				sessionBID = id
				break
			}
		}
	}
	f.sessionRepo.mu.RUnlock()
	if sessionBID == uuid.Nil {
		t.Fatalf("failed to find session B ID")
	}

	// 1. User A (authenticated with Bearer token A) attempts to revoke session B by passing session_id: sessionB
	{
		body, _ := json.Marshal(map[string]string{
			"session_id": sessionBID.String(),
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokensA.AccessToken)
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for cross-session revocation attempt, got %d: %s", rec.Code, rec.Body.String())
		}

		// Ensure Session B is still active
		active, _ := f.sessionRepo.IsActive(context.Background(), sessionBID)
		if !active {
			t.Errorf("Session B was improperly revoked by user A!")
		}
	}

	// 2. Unauthenticated caller attempts to pass refresh_token A with session_id B
	{
		body, _ := json.Marshal(map[string]string{
			"refresh_token": tokensA.RefreshToken,
			"session_id":    sessionBID.String(),
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden when refresh_token does not match session_id, got %d: %s", rec.Code, rec.Body.String())
		}

		// Ensure Session B is still active
		active, _ := f.sessionRepo.IsActive(context.Background(), sessionBID)
		if !active {
			t.Errorf("Session B was improperly revoked!")
		}
	}
}

func TestAuthHandler_Logout_UntrustedSessionID_Rejected(t *testing.T) {
	f := setupAuthFixture(t)

	// An untrusted session ID without Bearer token or refresh token must be rejected with 401
	body, _ := json.Marshal(map[string]string{
		"session_id": uuid.New().String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for untrusted session ID, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandler_Logout_InvalidCredentials_NeverReportsSuccess(t *testing.T) {
	f := setupAuthFixture(t)

	// 1. Unknown refresh token without Bearer token must return 401
	{
		body, _ := json.Marshal(map[string]string{
			"refresh_token": "unknown-nonexistent-token",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unknown refresh token, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 2. Empty body without Bearer token must return 400
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when no credentials supplied, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}
