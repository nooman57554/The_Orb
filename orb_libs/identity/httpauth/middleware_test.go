package httpauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/orb_libs/identity/httpauth"
)

type mockTokenVerifier struct {
	verifyFn func(token string) (*identity.Principal, error)
}

func (m *mockTokenVerifier) VerifyAccessToken(token string) (*identity.Principal, error) {
	if m.verifyFn != nil {
		return m.verifyFn(token)
	}
	return nil, errors.New("unimplemented")
}

type mockSessionChecker struct {
	isActiveFn func(ctx context.Context, sessionID uuid.UUID) (bool, error)
}

func (m *mockSessionChecker) IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error) {
	if m.isActiveFn != nil {
		return m.isActiveFn(ctx, sessionID)
	}
	return false, nil
}

func TestNewBearerMiddleware_Validation(t *testing.T) {
	checker := &mockSessionChecker{}

	// Nil verifier must fail
	if _, err := httpauth.NewBearerMiddleware(nil, checker); err == nil {
		t.Error("expected error when verifier is nil")
	}

	// Valid verifier with nil checker is allowed
	verifier := &mockTokenVerifier{}
	mw, err := httpauth.NewBearerMiddleware(verifier, nil)
	if err != nil || mw == nil {
		t.Fatalf("expected nil checker to be allowed, got err: %v", err)
	}

	// Valid verifier with checker and public routes
	mw2, err := httpauth.NewBearerMiddleware(verifier, checker, "POST /v1/auth/login", "POST /v1/users")
	if err != nil || mw2 == nil {
		t.Fatalf("expected valid middleware, got err: %v", err)
	}
}

func TestBearerMiddleware_DefaultProtected_MissingAuthHeader(t *testing.T) {
	verifier := &mockTokenVerifier{}
	mw, _ := httpauth.NewBearerMiddleware(verifier, nil)

	called := false
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem: %v", err)
	}
	if prob.Type != "https://orb.example.com/problems/unauthorized" {
		t.Errorf("expected unauthorized problem type, got %s", prob.Type)
	}
	if prob.Status != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, prob.Status)
	}
}

func TestBearerMiddleware_PublicRoute_Exempted(t *testing.T) {
	verifier := &mockTokenVerifier{
		verifyFn: func(token string) (*identity.Principal, error) {
			t.Error("verifier should NOT be called for public routes")
			return nil, errors.New("should not be called")
		},
	}
	mw, _ := httpauth.NewBearerMiddleware(verifier, nil, "POST /v1/auth/login", "POST /v1/users")

	called := false
	var contextPrincipal *identity.Principal
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		p, ok := identity.PrincipalFromContext(r.Context())
		if ok || p != nil {
			t.Errorf("expected no principal on public route context, got %v", p)
		}
		contextPrincipal = p
		w.WriteHeader(http.StatusOK)
	}))

	// 1. POST /v1/auth/login is public: works without any token
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected public route handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if contextPrincipal != nil {
		t.Errorf("expected nil principal on public route, got %v", contextPrincipal)
	}

	// 2. GET /v1/auth/login is NOT on the public allowlist: requires authentication
	called = false
	req2 := httptest.NewRequest(http.MethodGet, "/v1/auth/login", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if called {
		t.Fatal("expected non-public method to be protected and not reach handler")
	}
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for GET /v1/auth/login, got %d", rec2.Code)
	}

	// 3. POST /v1/users is public (registered via constructor)
	called = false
	req3 := httptest.NewRequest(http.MethodPost, "/v1/users", nil)
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)

	if !called {
		t.Fatal("expected POST /v1/users to be public")
	}
	if rec3.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec3.Code)
	}
}

func TestBearerMiddleware_AllowPublic_Method(t *testing.T) {
	verifier := &mockTokenVerifier{}
	mw, _ := httpauth.NewBearerMiddleware(verifier, nil)
	mw.AllowPublic("GET", "/healthz")

	called := false
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected /healthz to be exempted")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestBearerMiddleware_MalformedAuthorizationHeader(t *testing.T) {
	verifier := &mockTokenVerifier{}
	mw, _ := httpauth.NewBearerMiddleware(verifier, nil)

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
			handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))

			req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
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

func TestBearerMiddleware_InvalidOrExpiredToken(t *testing.T) {
	tests := []struct {
		name      string
		verifyErr error
	}{
		{name: "invalid signature", verifyErr: errors.New("invalid signature")},
		{name: "expired token", verifyErr: errors.New("token is expired")},
		{name: "malformed token", verifyErr: errors.New("token is malformed")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &mockTokenVerifier{
				verifyFn: func(token string) (*identity.Principal, error) {
					return nil, tc.verifyErr
				},
			}
			mw, _ := httpauth.NewBearerMiddleware(verifier, nil)

			called := false
			handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
			}))

			req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
			req.Header.Set("Authorization", "Bearer some-token")
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

func TestBearerMiddleware_InvalidPrincipal(t *testing.T) {
	verifier := &mockTokenVerifier{
		verifyFn: func(token string) (*identity.Principal, error) {
			return &identity.Principal{
				UserID:    uuid.Nil,
				SessionID: uuid.New(),
				TokenID:   uuid.New(),
			}, nil
		},
	}
	mw, _ := httpauth.NewBearerMiddleware(verifier, nil)

	called := false
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer token-with-nil-user")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestBearerMiddleware_InactiveSession(t *testing.T) {
	principal := &identity.Principal{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	verifier := &mockTokenVerifier{
		verifyFn: func(token string) (*identity.Principal, error) {
			return principal, nil
		},
	}
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return false, nil
		},
	}
	mw, _ := httpauth.NewBearerMiddleware(verifier, checker)

	called := false
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called for inactive session")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestBearerMiddleware_SessionCheckFailure_Returns503(t *testing.T) {
	principal := &identity.Principal{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	verifier := &mockTokenVerifier{
		verifyFn: func(token string) (*identity.Principal, error) {
			return principal, nil
		},
	}
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return false, errors.New("database connection failure")
		},
	}
	mw, _ := httpauth.NewBearerMiddleware(verifier, checker)

	called := false
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if called {
		t.Error("expected protected handler not to be called when session check fails")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status %d, got %d", http.StatusServiceUnavailable, rec.Code)
	}

	var prob httpx.ProblemDetails
	if err := json.NewDecoder(rec.Body).Decode(&prob); err != nil {
		t.Fatalf("failed to decode problem JSON: %v", err)
	}
	if prob.Type != "https://orb.example.com/problems/service-unavailable" {
		t.Errorf("expected service-unavailable problem type, got %s", prob.Type)
	}
	if prob.Detail == "database connection failure" {
		t.Error("internal database error message was leaked to client")
	}
}

func TestBearerMiddleware_ValidPrincipal_ContextPropagation(t *testing.T) {
	expectedPrincipal := &identity.Principal{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	verifier := &mockTokenVerifier{
		verifyFn: func(token string) (*identity.Principal, error) {
			return expectedPrincipal, nil
		},
	}
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	mw, _ := httpauth.NewBearerMiddleware(verifier, checker)

	called := false
	var downstreamPrincipal *identity.Principal
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		p, ok := identity.PrincipalFromContext(r.Context())
		if !ok {
			t.Error("expected principal to be present in context")
		}
		downstreamPrincipal = p
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected downstream handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if downstreamPrincipal == nil {
		t.Fatal("downstream principal is nil")
	}
	if downstreamPrincipal.UserID != expectedPrincipal.UserID {
		t.Errorf("expected user ID %s, got %s", expectedPrincipal.UserID, downstreamPrincipal.UserID)
	}
}

func TestBearerMiddleware_SpoofedHeadersIgnored(t *testing.T) {
	realPrincipal := &identity.Principal{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	spoofedUserID := uuid.New()

	verifier := &mockTokenVerifier{
		verifyFn: func(token string) (*identity.Principal, error) {
			return realPrincipal, nil
		},
	}
	checker := &mockSessionChecker{
		isActiveFn: func(ctx context.Context, sessionID uuid.UUID) (bool, error) {
			return true, nil
		},
	}
	mw, _ := httpauth.NewBearerMiddleware(verifier, checker)

	var downstreamPrincipal *identity.Principal
	handler := mw.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := identity.PrincipalFromContext(r.Context())
		downstreamPrincipal = p
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("X-User-ID", spoofedUserID.String())
	req.Header.Set("X-Authenticated-User", spoofedUserID.String())
	req.Header.Set("X-Tenant-ID", uuid.New().String())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if downstreamPrincipal.UserID != realPrincipal.UserID {
		t.Errorf("expected verified principal user ID %s, got %s", realPrincipal.UserID, downstreamPrincipal.UserID)
	}
}
