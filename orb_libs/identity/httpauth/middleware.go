package httpauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

// SessionChecker verifies whether a session is currently active.
// It is an optional dependency for BearerMiddleware.
type SessionChecker interface {
	IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error)
}

// BearerMiddleware authenticates HTTP requests using Bearer tokens and
// injects the verified identity.Principal into the request context.
type BearerMiddleware struct {
	verifier       identity.TokenVerifier
	sessionChecker SessionChecker
}

// NewBearerMiddleware creates a new BearerMiddleware instance.
// Verifier is required. SessionChecker is optional (pass nil to disable session checks).
func NewBearerMiddleware(verifier identity.TokenVerifier, sessionChecker SessionChecker) (*BearerMiddleware, error) {
	if verifier == nil {
		return nil, fmt.Errorf("token verifier is required")
	}

	return &BearerMiddleware{
		verifier:       verifier,
		sessionChecker: sessionChecker,
	}, nil
}

// Require wraps an http.Handler with bearer token authentication and session state checks.
func (m *BearerMiddleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Authorization header is required.",
			)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" || strings.ContainsAny(parts[1], " \t\r\n") {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Invalid authorization header format.",
			)
			return
		}

		tokenString := parts[1]

		principal, err := m.verifier.VerifyAccessToken(tokenString)
		if err != nil {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Invalid or expired access token.",
			)
			return
		}

		if principal == nil || !principal.IsValid() {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Invalid access token claims.",
			)
			return
		}

		if m.sessionChecker != nil {
			active, err := m.sessionChecker.IsActive(r.Context(), principal.SessionID)
			if err != nil {
				httpx.WriteProblem(
					w,
					http.StatusServiceUnavailable,
					"Service Unavailable",
					"Authentication service is temporarily unavailable.",
				)
				return
			}

			if !active {
				httpx.WriteProblem(
					w,
					http.StatusUnauthorized,
					"Unauthorized",
					"Session is invalid, expired, or revoked.",
				)
				return
			}
		}

		ctx := identity.WithPrincipal(r.Context(), principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
