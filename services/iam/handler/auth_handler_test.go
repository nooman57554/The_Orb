package handler_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
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
	sessionsByPrevHash  map[string]*model.Session
	userRepo            repository.UserRepository
	forceRevokeError    bool
	forceGetError       bool
	forceRotateNotFound bool
	forceGetPrevError   bool
}

func newMockSessionRepository(userRepo repository.UserRepository) *mockSessionRepository {
	return &mockSessionRepository{
		sessionsByID:        make(map[uuid.UUID]*model.Session),
		sessionsByTokenHash: make(map[string]*model.Session),
		sessionsByPrevHash:  make(map[string]*model.Session),
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

	if m.forceGetError {
		return nil, errors.New("database connection failure")
	}

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

func (m *mockSessionRepository) GetByPreviousTokenHash(ctx context.Context, tokenHash string) (*model.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.forceGetError || m.forceGetPrevError {
		return nil, errors.New("database connection failure")
	}

	s, ok := m.sessionsByPrevHash[tokenHash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	copy := *s
	return &copy, nil
}

func (m *mockSessionRepository) RotateRefreshToken(ctx context.Context, oldTokenHash, newTokenHash string) (*model.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.forceRotateNotFound {
		return nil, repository.ErrNotFound
	}

	s, ok := m.sessionsByTokenHash[oldTokenHash]
	if !ok || s.RevokedAt != nil || time.Now().After(s.ExpiresAt) {
		return nil, repository.ErrNotFound
	}

	delete(m.sessionsByTokenHash, oldTokenHash)
	m.sessionsByPrevHash[oldTokenHash] = s
	m.sessionsByTokenHash[newTokenHash] = s
	now := time.Now()
	s.RotatedAt = &now
	prevHash := oldTokenHash
	s.PreviousTokenHash = &prevHash
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

	if m.forceRevokeError {
		return errors.New("database connection refused: i/o timeout")
	}

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
	privKey          ed25519.PrivateKey
	keyID            string
}

func (f *authTestFixture) createExpiredToken(t *testing.T, userID, sessionID uuid.UUID) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": "orb-iam",
		"sub": userID.String(),
		"aud": []string{"orb-platform"},
		"sid": sessionID.String(),
		"jti": uuid.New().String(),
		"exp": time.Now().Add(-5 * time.Minute).Unix(),
		"iat": time.Now().Add(-20 * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = f.keyID
	tokenString, err := token.SignedString(f.privKey)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}
	return tokenString
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
	return setupAuthFixtureWithGracePeriod(t, 15*time.Second)
}

func setupAuthFixtureWithGracePeriod(t *testing.T, gracePeriod time.Duration) *authTestFixture {
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
		gracePeriod,
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
		privKey:          priv,
		keyID:            keyID,
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
// Strict Logout Tests
// -----------------------------------------------------------------------------

func TestAuthHandler_Logout_MissingBearerToken_Returns401(t *testing.T) {
	f := setupAuthFixture(t)

	// Missing Bearer token returns 401
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing bearer token, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandler_Logout_InvalidOrExpiredAccessToken_Returns401(t *testing.T) {
	f := setupAuthFixture(t)

	userID := uuid.New()
	sessionID := uuid.New()

	// 1. Invalid signature / malformed token
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer invalid.signature.token")
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for invalid signature, got %d: %s", rec.Code, rec.Body.String())
		}
	}

	// 2. Expired access token
	{
		expiredToken := f.createExpiredToken(t, userID, sessionID)
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for expired token, got %d: %s", rec.Code, rec.Body.String())
		}
	}
}

func TestAuthHandler_Logout_ValidBearerToken_RevokesOwnSession_Returns204(t *testing.T) {
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

	// Find the session ID
	var sessionID uuid.UUID
	f.sessionRepo.mu.RLock()
	for id, s := range f.sessionRepo.sessionsByID {
		u, _ := f.userRepo.GetByID(context.Background(), s.UserID)
		if u != nil && u.Email == "logout_user@example.com" {
			sessionID = id
			break
		}
	}
	f.sessionRepo.mu.RUnlock()
	if sessionID == uuid.Nil {
		t.Fatalf("session not found")
	}

	// Authenticated logout via Bearer token
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d: %s", rec.Code, rec.Body.String())
	}

	// Assert session is revoked
	active, _ := f.sessionRepo.IsActive(context.Background(), sessionID)
	if active {
		t.Errorf("session should be inactive after logout")
	}
	f.sessionRepo.mu.RLock()
	sessionRecord := f.sessionRepo.sessionsByID[sessionID]
	f.sessionRepo.mu.RUnlock()
	if sessionRecord.RevokedAt == nil {
		t.Errorf("expected RevokedAt to be set")
	}
}

func TestAuthHandler_Logout_RepeatedLogout_Idempotent_PreservesTimestamp(t *testing.T) {
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "repeat_user@example.com",
		Password: "password123!",
	})

	tokens, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "repeat_user@example.com",
		Password: "password123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// First logout
	req1 := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req1.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec1 := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d: %s", rec1.Code, rec1.Body.String())
	}

	var sessionID uuid.UUID
	var firstRevokedAt time.Time
	f.sessionRepo.mu.RLock()
	for id, s := range f.sessionRepo.sessionsByID {
		u, _ := f.userRepo.GetByID(context.Background(), s.UserID)
		if u != nil && u.Email == "repeat_user@example.com" {
			sessionID = id
			firstRevokedAt = *s.RevokedAt
			break
		}
	}
	f.sessionRepo.mu.RUnlock()

	time.Sleep(15 * time.Millisecond)

	// Second logout for the same signed session must return 204 without changing original revocation timestamp
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req2.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec2 := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for repeated logout, got %d: %s", rec2.Code, rec2.Body.String())
	}

	f.sessionRepo.mu.RLock()
	secondRevokedAt := *f.sessionRepo.sessionsByID[sessionID].RevokedAt
	f.sessionRepo.mu.RUnlock()

	if !secondRevokedAt.Equal(firstRevokedAt) {
		t.Errorf("revocation timestamp changed on repeated logout! first: %v, second: %v", firstRevokedAt, secondRevokedAt)
	}
}

func TestAuthHandler_Logout_AlreadyRevokedSession_ReachesIdempotentRevocation(t *testing.T) {
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "prerevoked@example.com",
		Password: "password123!",
	})

	tokens, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "prerevoked@example.com",
		Password: "password123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Manually pre-revoke the session with an earlier timestamp
	pastRevokedAt := time.Now().Add(-1 * time.Hour).Truncate(time.Millisecond)
	var sessionID uuid.UUID
	f.sessionRepo.mu.Lock()
	for id, s := range f.sessionRepo.sessionsByID {
		u, _ := f.userRepo.GetByID(context.Background(), s.UserID)
		if u != nil && u.Email == "prerevoked@example.com" {
			sessionID = id
			s.RevokedAt = &pastRevokedAt
			break
		}
	}
	f.sessionRepo.mu.Unlock()

	// A valid signed token for an already-revoked session can still reach the idempotent revocation path
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for already revoked session, got %d: %s", rec.Code, rec.Body.String())
	}

	f.sessionRepo.mu.RLock()
	currentRevokedAt := *f.sessionRepo.sessionsByID[sessionID].RevokedAt
	f.sessionRepo.mu.RUnlock()

	if !currentRevokedAt.Equal(pastRevokedAt) {
		t.Errorf("expected original revocation timestamp %v preserved, got %v", pastRevokedAt, currentRevokedAt)
	}
}

func TestAuthHandler_Logout_SafeDuringConcurrentRefreshRotation(t *testing.T) {
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "concurrent_user@example.com",
		Password: "password123!",
	})

	tokens1, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "concurrent_user@example.com",
		Password: "password123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Refresh rotates refresh token from tokens1 to tokens2
	tokens2, err := f.authService.Refresh(context.Background(), tokens1.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// Client racing: logout using previously issued tokens1.AccessToken
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokens1.AccessToken)
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d: %s", rec.Code, rec.Body.String())
	}

	// Session is revoked: subsequent refresh with tokens2 fails
	_, err = f.authService.Refresh(context.Background(), tokens2.RefreshToken)
	if !errors.Is(err, service.ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken after logout, got %v", err)
	}
}

func TestAuthHandler_Logout_DatabaseFailure_Returns500AndNeverReportsSuccess(t *testing.T) {
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "dbfail_user@example.com",
		Password: "password123!",
	})

	tokens, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "dbfail_user@example.com",
		Password: "password123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Simulate database failure during revocation
	f.sessionRepo.forceRevokeError = true

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error when database fails, got %d: %s", rec.Code, rec.Body.String())
	}

	var prob struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if prob.Status != http.StatusInternalServerError {
		t.Errorf("expected problem status 500, got %d", prob.Status)
	}
}

func TestAuthHandler_Logout_BodyCannotRedirectRevocationToAnotherSession(t *testing.T) {
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

	var sessionAID, sessionBID uuid.UUID
	f.sessionRepo.mu.RLock()
	for id, s := range f.sessionRepo.sessionsByID {
		u, _ := f.userRepo.GetByID(context.Background(), s.UserID)
		if u != nil {
			if u.Email == "user_a@example.com" {
				sessionAID = id
			} else if u.Email == "user_b@example.com" {
				sessionBID = id
			}
		}
	}
	f.sessionRepo.mu.RUnlock()

	// User A attempts to redirect revocation to Session B by sending Session B ID and RefreshToken in request body
	body, _ := json.Marshal(map[string]string{
		"session_id":    sessionBID.String(),
		"refresh_token": tokensB.RefreshToken,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tokensA.AccessToken)
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for caller's own session, got %d: %s", rec.Code, rec.Body.String())
	}

	// Verify Session A is revoked
	activeA, _ := f.sessionRepo.IsActive(context.Background(), sessionAID)
	if activeA {
		t.Errorf("User A's session should have been revoked")
	}

	// CRITICAL: Verify Session B is STILL ACTIVE and was NOT revoked by User A's body payload
	activeB, _ := f.sessionRepo.IsActive(context.Background(), sessionBID)
	if !activeB {
		t.Errorf("Session B was improperly revoked! Client-supplied body was able to redirect revocation!")
	}
	f.sessionRepo.mu.RLock()
	sessionBRecord := f.sessionRepo.sessionsByID[sessionBID]
	f.sessionRepo.mu.RUnlock()
	if sessionBRecord.RevokedAt != nil {
		t.Errorf("Session B RevokedAt should be nil, but got %v", sessionBRecord.RevokedAt)
	}
}

// -----------------------------------------------------------------------------
// Milestone 2B Tests: Refresh-Token Reuse Detection & Concurrency
// -----------------------------------------------------------------------------

func TestAuthHandler_Refresh_SuccessAndRotation(t *testing.T) {
	f := setupAuthFixture(t)
	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "refresh_user@example.com",
		Password: "Password123!",
	})

	tokens1, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "refresh_user@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"refresh_token": tokens1.RefreshToken,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var tokens2 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&tokens2); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}

	if tokens2.RefreshToken == "" || tokens2.RefreshToken == tokens1.RefreshToken {
		t.Errorf("expected new distinct refresh token, got %q", tokens2.RefreshToken)
	}
	if tokens2.AccessToken == "" {
		t.Error("expected non-empty access token")
	}

	// Verify session in repository has been rotated
	f.sessionRepo.mu.RLock()
	var rotatedSession *model.Session
	for _, s := range f.sessionRepo.sessionsByID {
		rotatedSession = s
		break
	}
	f.sessionRepo.mu.RUnlock()

	if rotatedSession == nil {
		t.Fatal("session not found in repository")
	}
	if rotatedSession.PreviousTokenHash == nil {
		t.Error("expected PreviousTokenHash to be populated after rotation")
	}
	if rotatedSession.RotatedAt == nil {
		t.Error("expected RotatedAt timestamp to be populated after rotation")
	}
}

func TestAuthHandler_Refresh_InvalidAndExpiredTokens(t *testing.T) {
	f := setupAuthFixture(t)
	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "user_expire@example.com",
		Password: "Password123!",
	})

	// 1. Empty refresh token -> 400 Bad Request
	{
		body, _ := json.Marshal(map[string]string{
			"refresh_token": "",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 Bad Request for empty refresh token, got %d", rec.Code)
		}
	}

	// 2. Random unknown refresh token -> 401 Unauthorized
	{
		body, _ := json.Marshal(map[string]string{
			"refresh_token": "non_existent_random_token_12345",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for unknown token, got %d", rec.Code)
		}
	}

	// 3. Expired refresh token -> 401 Unauthorized
	{
		tokens, _ := f.authService.Login(context.Background(), service.LoginInput{
			Email:    "user_expire@example.com",
			Password: "Password123!",
		})

		// Artificially expire the session in the repository
		f.sessionRepo.mu.Lock()
		for _, s := range f.sessionRepo.sessionsByID {
			s.ExpiresAt = time.Now().Add(-1 * time.Hour)
		}
		f.sessionRepo.mu.Unlock()

		body, _ := json.Marshal(map[string]string{
			"refresh_token": tokens.RefreshToken,
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		f.appHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized for expired refresh token, got %d", rec.Code)
		}
	}
}

func TestAuthService_NewAuthService_GracePeriodValidation(t *testing.T) {
	userRepo := &mockUserRepositoryWithDBErrors{
		mockUserRepository: *newMockUserRepository(),
	}
	sessionRepo := newMockSessionRepository(userRepo)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwtManager, _ := auth.NewJWTManager(priv, "k1", "orb-iam", "orb-platform", 15*time.Minute)

	tests := []struct {
		name        string
		gracePeriod time.Duration
		wantErr     bool
	}{
		{
			name:        "zero grace period rejected",
			gracePeriod: 0,
			wantErr:     true,
		},
		{
			name:        "negative grace period rejected",
			gracePeriod: -5 * time.Second,
			wantErr:     true,
		},
		{
			name:        "positive grace period accepted",
			gracePeriod: 15 * time.Second,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.NewAuthService(
				userRepo,
				sessionRepo,
				jwtManager,
				15*time.Minute,
				24*time.Hour,
				tt.gracePeriod,
			)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for grace period %v, got nil", tt.gracePeriod)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for grace period %v: %v", tt.gracePeriod, err)
			}
		})
	}
}

func TestAuthHandler_Refresh_ReuseOfPreviouslyRotatedToken_RevokesSession(t *testing.T) {
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "reuse_victim@example.com",
		Password: "Password123!",
	})

	tokens1, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "reuse_victim@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// 1. Legitimate user rotates RT1 -> RT2
	body1, _ := json.Marshal(map[string]string{"refresh_token": tokens1.RefreshToken})
	req1 := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body1))
	rec1 := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first refresh failed: %d: %s", rec1.Code, rec1.Body.String())
	}

	var tokens2 struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(rec1.Body).Decode(&tokens2)

	// Artificially backdate RotatedAt on the session so the reuse attempt falls outside the grace period
	f.sessionRepo.mu.Lock()
	past := time.Now().Add(-1 * time.Minute)
	for _, s := range f.sessionRepo.sessionsByID {
		if s.RotatedAt != nil {
			s.RotatedAt = &past
		}
	}
	f.sessionRepo.mu.Unlock()

	// 2. Attacker replays RT1 (previously rotated token outside grace window)
	bodyReplay, _ := json.Marshal(map[string]string{"refresh_token": tokens1.RefreshToken})
	reqReplay := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(bodyReplay))
	recReplay := httptest.NewRecorder()
	f.appHandler.ServeHTTP(recReplay, reqReplay)

	if recReplay.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on reuse, got %d", recReplay.Code)
	}

	// 3. Security response check: The entire session must now be REVOKED
	var sessionID uuid.UUID
	f.sessionRepo.mu.RLock()
	for id, s := range f.sessionRepo.sessionsByID {
		sessionID = id
		if s.RevokedAt == nil {
			t.Errorf("session %s should be revoked after token reuse, but RevokedAt is nil", id)
		}
	}
	f.sessionRepo.mu.RUnlock()

	active, _ := f.sessionRepo.IsActive(context.Background(), sessionID)
	if active {
		t.Errorf("session should be inactive after token reuse")
	}

	// 4. Legitimate user holding RT2 now attempts to refresh -> rejected because session is revoked!
	body2, _ := json.Marshal(map[string]string{"refresh_token": tokens2.RefreshToken})
	req2 := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body2))
	rec2 := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized for RT2 after session revoked by reuse, got %d", rec2.Code)
	}
}

func TestAuthHandler_Refresh_ConcurrentRefresh_OneWins_LosingDoesNotRevoke(t *testing.T) {
	// 15s default grace period handles in-flight concurrent races
	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "concurrent_user@example.com",
		Password: "Password123!",
	})

	tokens, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "concurrent_user@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	const concurrency = 2
	results := make(chan int, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]string{
				"refresh_token": tokens.RefreshToken,
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			f.appHandler.ServeHTTP(rec, req)
			results <- rec.Code
		}()
	}

	wg.Wait()
	close(results)

	var successCount, failureCount int
	for code := range results {
		if code == http.StatusOK {
			successCount++
		} else if code == http.StatusUnauthorized {
			failureCount++
		} else {
			t.Errorf("unexpected status code %d in concurrent refresh", code)
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 winner, got %d", successCount)
	}
	if failureCount != 1 {
		t.Errorf("expected exactly 1 losing request (401), got %d", failureCount)
	}

	// CRITICAL: The session must NOT be revoked! In-flight concurrent race within grace period is benign.
	f.sessionRepo.mu.RLock()
	var session *model.Session
	for _, s := range f.sessionRepo.sessionsByID {
		session = s
		break
	}
	f.sessionRepo.mu.RUnlock()

	if session == nil || session.RevokedAt != nil {
		t.Fatalf("session was improperly revoked by concurrent race! RevokedAt = %v", session.RevokedAt)
	}

	active, _ := f.sessionRepo.IsActive(context.Background(), session.ID)
	if !active {
		t.Error("winning session should still be active")
	}
}

func TestAuthHandler_Refresh_ConcurrentRace_DatabaseFailure_Returns500(t *testing.T) {
	f := setupAuthFixture(t)
	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "concurrent_db_err@example.com",
		Password: "Password123!",
	})

	tokens, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "concurrent_db_err@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Simulate concurrency race:
	// Initial lookup GetByRefreshTokenHash succeeds.
	// RotateRefreshToken returns repository.ErrNotFound (another request won the race).
	// Subsequent GetByPreviousTokenHash fails with a database error.
	f.sessionRepo.mu.Lock()
	f.sessionRepo.forceRotateNotFound = true
	f.sessionRepo.forceGetPrevError = true
	f.sessionRepo.mu.Unlock()

	body, _ := json.Marshal(map[string]string{
		"refresh_token": tokens.RefreshToken,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error when GetByPreviousTokenHash fails after concurrent rotation, got %d: %s", rec.Code, rec.Body.String())
	}

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem: %v", err)
	}
	if prob.Detail == "database connection failure" {
		t.Error("internal database error message leaked to client")
	}
}

func TestAuthHandler_Refresh_ConcurrentRace_NotFoundInPrevious_Returns401(t *testing.T) {
	f := setupAuthFixture(t)
	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "concurrent_notfound@example.com",
		Password: "Password123!",
	})

	tokens, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "concurrent_notfound@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Simulate concurrency race where RotateRefreshToken returns ErrNotFound,
	// and GetByPreviousTokenHash also returns repository.ErrNotFound.
	f.sessionRepo.mu.Lock()
	f.sessionRepo.forceRotateNotFound = true
	f.sessionRepo.forceGetPrevError = false
	f.sessionRepo.mu.Unlock()

	body, _ := json.Marshal(map[string]string{
		"refresh_token": tokens.RefreshToken,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized when GetByPreviousTokenHash returns ErrNotFound after concurrent rotation, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHandler_Refresh_InitialLookupNotFound_PreviousTokenDBError_Returns500(t *testing.T) {
	f := setupAuthFixture(t)

	// Simulate initial lookup returning ErrNotFound (token not active),
	// followed by GetByPreviousTokenHash failing with a database error.
	f.sessionRepo.mu.Lock()
	f.sessionRepo.forceGetPrevError = true
	f.sessionRepo.mu.Unlock()

	body, _ := json.Marshal(map[string]string{
		"refresh_token": "random_inactive_refresh_token_xyz",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error when GetByPreviousTokenHash fails on inactive token check, got %d: %s", rec.Code, rec.Body.String())
	}

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem: %v", err)
	}
	if prob.Detail == "database connection failure" {
		t.Error("internal database error message leaked to client")
	}
}

func TestAuthHandler_Refresh_DatabaseFailure_Returns500(t *testing.T) {
	f := setupAuthFixture(t)
	userService := service.NewUserService(f.userRepo)
	_, _ = userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "db_fail_user@example.com",
		Password: "Password123!",
	})

	tokens, _ := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "db_fail_user@example.com",
		Password: "Password123!",
	})

	// Inject database connection failure
	f.sessionRepo.forceGetError = true

	body, _ := json.Marshal(map[string]string{
		"refresh_token": tokens.RefreshToken,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error on database failure, got %d: %s", rec.Code, rec.Body.String())
	}

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem: %v", err)
	}
	if prob.Detail == "database connection failure" {
		t.Error("internal database error message leaked to client")
	}
}

func TestAuthHandler_Refresh_NoRawTokenInLogsOrResponse(t *testing.T) {
	// Capture logger output and restore global logger state after test
	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&logBuf)
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	})

	f := setupAuthFixture(t)

	userService := service.NewUserService(f.userRepo)
	_, err := userService.CreateUser(context.Background(), service.CreateUserInput{
		Email:    "secrecy_user@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	tokens1, err := f.authService.Login(context.Background(), service.LoginInput{
		Email:    "secrecy_user@example.com",
		Password: "Password123!",
	})
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}

	rawSecretToken := tokens1.RefreshToken
	sum := sha256.Sum256([]byte(rawSecretToken))
	sha256Hash := hex.EncodeToString(sum[:])

	// Legitimate rotation RT1 -> RT2
	body1, _ := json.Marshal(map[string]string{"refresh_token": rawSecretToken})
	req1 := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(body1))
	rec1 := httptest.NewRecorder()
	f.appHandler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 on initial rotation, got %d: %s", rec1.Code, rec1.Body.String())
	}

	// Backdate RotatedAt so the token reuse attempt falls outside the grace period
	f.sessionRepo.mu.Lock()
	past := time.Now().Add(-1 * time.Minute)
	for _, s := range f.sessionRepo.sessionsByID {
		if s.RotatedAt != nil {
			s.RotatedAt = &past
		}
	}
	f.sessionRepo.mu.Unlock()

	// Replay old refresh token (RT1) -> triggers token reuse detection and security log
	bodyReplay, _ := json.Marshal(map[string]string{"refresh_token": rawSecretToken})
	reqReplay := httptest.NewRequest(http.MethodPost, "/v1/auth/refresh", bytes.NewReader(bodyReplay))
	recReplay := httptest.NewRecorder()
	f.appHandler.ServeHTTP(recReplay, reqReplay)

	if recReplay.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized on reuse, got %d", recReplay.Code)
	}

	logOutput := logBuf.String()
	// Verify that the security event was logged
	if !strings.Contains(logOutput, "SECURITY: refresh token reuse detected for session") {
		t.Errorf("expected security log message to be emitted, got: %q", logOutput)
	}

	// Secrecy assertions for logs
	if strings.Contains(logOutput, rawSecretToken) {
		t.Errorf("raw secret refresh token leaked in logger output: %s", logOutput)
	}
	if strings.Contains(logOutput, sha256Hash) {
		t.Errorf("SHA-256 hash of refresh token leaked in logger output: %s", logOutput)
	}

	// Secrecy assertions for client HTTP response
	responseBody := recReplay.Body.String()
	if strings.Contains(responseBody, rawSecretToken) {
		t.Errorf("raw secret refresh token leaked in response body: %s", responseBody)
	}
	if strings.Contains(responseBody, sha256Hash) {
		t.Errorf("SHA-256 hash of refresh token leaked in response body: %s", responseBody)
	}
}
