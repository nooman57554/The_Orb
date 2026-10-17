package middleware_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/auth"
	"github.com/nooman57554/The_Orb/services/iam/middleware"
)

type mockSessionChecker struct {
	isActiveFn func(ctx context.Context, sessionID uuid.UUID) (bool, error)
}

func (m *mockSessionChecker) IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	if m.isActiveFn != nil {
		return m.isActiveFn(ctx, sessionID)
	}
	return false, nil
}

type testFixture struct {
	jwtManager *auth.JWTManager
	privKey    ed25519.PrivateKey
	pubKey     ed25519.PublicKey
	keyID      string
	issuer     string
	audience   string
}

func setupFixture(t *testing.T) *testFixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	keyID := "test-key-1"
	issuer := "orb-iam-test"
	audience := "orb-platform-test"

	manager, err := auth.NewJWTManager(
		priv,
		keyID,
		map[string]ed25519.PublicKey{keyID: pub},
		issuer,
		audience,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("failed to create JWT manager: %v", err)
	}

	return &testFixture{
		jwtManager: manager,
		privKey:    priv,
		pubKey:     pub,
		keyID:      keyID,
		issuer:     issuer,
		audience:   audience,
	}
}

func TestNewAuthMiddleware_Validation(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{}

	if _, err := middleware.NewAuthMiddleware(nil, checker); err == nil {
		t.Error("expected error when verifier is nil")
	}
	if _, err := middleware.NewAuthMiddleware(f.jwtManager, nil); err == nil {
		t.Error("expected error when session checker is nil")
	}
	mw, err := middleware.NewAuthMiddleware(f.jwtManager, checker)
	if err != nil || mw == nil {
		t.Fatalf("expected valid middleware, got err: %v", err)
	}
}

func TestAuthMiddleware_MissingAuthorizationHeader(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	called := false
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	var prob struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem response: %v", err)
	}
	if prob.Type != "https://orb.example.com/problems/unauthorized" {
		t.Errorf("expected unauthorized problem type, got %s", prob.Type)
	}
	if prob.Status != http.StatusUnauthorized {
		t.Errorf("expected problem status %d, got %d", http.StatusUnauthorized, prob.Status)
	}
}

func TestAuthMiddleware_MalformedAuthorizationHeader(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	testCases := []struct {
		name   string
		header string
	}{
		{name: "invalid scheme basic", header: "Basic dXNlcjpwYXNz"},
		{name: "invalid scheme lowercase bearer", header: "bearer some-token"},
		{name: "bearer only without token", header: "Bearer"},
		{name: "bearer with only trailing space", header: "Bearer "},
		{name: "bearer with multiple spaces", header: "Bearer   token"},
		{name: "bearer with extra tokens", header: "Bearer token extra"},
		{name: "bearer with tab character", header: "Bearer token\textra"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))

			req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
			req.Header.Set("Authorization", tc.header)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if called {
				t.Error("expected protected handler not to be called")
			}
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
			}
		})
	}
}

func TestAuthMiddleware_InvalidSignature(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	// Create manager with a different key
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	otherManager, err := auth.NewJWTManager(
		otherPriv,
		f.keyID,
		map[string]ed25519.PublicKey{f.keyID: otherPriv.Public().(ed25519.PublicKey)},
		f.issuer,
		f.audience,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("other manager: %v", err)
	}

	token, err := otherManager.CreateAccessToken(auth.Claims{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	called := false
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAuthMiddleware_MalformedJWT(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	called := false
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAuthMiddleware_ExpiredJWT(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	// Craft expired JWT
	now := time.Now()
	type jwtClaims struct {
		SessionID string `json:"sid"`
		jwt.RegisteredClaims
	}
	jc := jwtClaims{
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(-10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-20 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-20 * time.Minute)),
			ID:        uuid.New().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jc)
	token.Header["kid"] = f.keyID
	tokenString, err := token.SignedString(f.privKey)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	called := false
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAuthMiddleware_RevokedSession(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			// Revoked session returns false, nil
			return false, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	token, err := f.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	called := false
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called for revoked session")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAuthMiddleware_ExpiredSession(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			// Expired session returns false, nil
			return false, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	token, err := f.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	called := false
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called for expired session")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAuthMiddleware_SessionRepositoryFailure(t *testing.T) {
	f := setupFixture(t)
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return false, errors.New("database connection pool exhausted")
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	token, err := f.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	called := false
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called when session repo fails")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}

	var prob struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if prob.Type != "https://orb.example.com/problems/service-unavailable" {
		t.Errorf("expected service-unavailable problem type, got %s", prob.Type)
	}
	// Verify no internal DB error message is exposed
	if prob.Detail == "database connection pool exhausted" {
		t.Error("database error was leaked to client")
	}
}

func TestAuthMiddleware_ValidJWT_ActiveSession(t *testing.T) {
	f := setupFixture(t)

	expectedUserID := uuid.New()
	expectedSessionID := uuid.New()
	expectedTokenID := uuid.New()

	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			if sessionID == expectedSessionID {
				return true, nil
			}
			return false, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	token, err := f.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    expectedUserID,
		SessionID: expectedSessionID,
		TokenID:   expectedTokenID,
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	called := false
	var retrievedClaims *auth.Claims
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		claims, ok := middleware.ClaimsFromContext(r.Context())
		if !ok {
			t.Error("expected claims in context")
		}
		retrievedClaims = claims
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if retrievedClaims == nil {
		t.Fatal("retrieved claims is nil")
	}
	if retrievedClaims.UserID != expectedUserID {
		t.Errorf("expected user ID %v, got %v", expectedUserID, retrievedClaims.UserID)
	}
	if retrievedClaims.SessionID != expectedSessionID {
		t.Errorf("expected session ID %v, got %v", expectedSessionID, retrievedClaims.SessionID)
	}
	if retrievedClaims.TokenID != expectedTokenID {
		t.Errorf("expected token ID %v, got %v", expectedTokenID, retrievedClaims.TokenID)
	}
}

func TestAuthMiddleware_IdentityFromVerifiedClaimsNotHeaders(t *testing.T) {
	f := setupFixture(t)

	realUserID := uuid.New()
	spoofedUserID := uuid.New()
	sessionID := uuid.New()

	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sid uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	mw, _ := middleware.NewAuthMiddleware(f.jwtManager, checker)

	token, err := f.jwtManager.CreateAccessToken(auth.Claims{
		UserID:    realUserID,
		SessionID: sessionID,
		TokenID:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	var contextUserID uuid.UUID
	handler := mw.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := middleware.ClaimsFromContext(r.Context())
		if !ok {
			t.Error("expected claims in context")
			return
		}
		contextUserID = claims.UserID
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/users/"+realUserID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// Attempt to spoof user identity via client headers
	req.Header.Set("X-User-ID", spoofedUserID.String())
	req.Header.Set("X-Authenticated-User", spoofedUserID.String())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if contextUserID != realUserID {
		t.Errorf("expected context user ID to be real token user %v, but got %v", realUserID, contextUserID)
	}
}
