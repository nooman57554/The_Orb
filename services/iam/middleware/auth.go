package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/auth"
)

// TokenVerifier verifies access tokens and returns the extracted claims.
type TokenVerifier interface {
	VerifyAccessToken(tokenString string) (*auth.Claims, error)
}

// SessionChecker verifies whether a session is currently active.
type SessionChecker interface {
	IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error)
}

var _ TokenVerifier = (*auth.JWTManager)(nil)

type contextKey struct{}

var claimsContextKey = contextKey{}

// WithClaims places verified claims into the given context.
func WithClaims(ctx context.Context, claims *auth.Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext safely retrieves verified claims from the context.
func ClaimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*auth.Claims)
	if !ok || claims == nil {
		return nil, false
	}
	return claims, true
}

// AuthMiddleware enforces bearer token authentication and session state checks.
type AuthMiddleware struct {
	verifier       TokenVerifier
	sessionChecker SessionChecker
}

// NewAuthMiddleware constructs a new AuthMiddleware with the supplied dependencies.
func NewAuthMiddleware(verifier TokenVerifier, sessionChecker SessionChecker) (*AuthMiddleware, error) {
	if verifier == nil {
		return nil, fmt.Errorf("token verifier is required")
	}
	if sessionChecker == nil {
		return nil, fmt.Errorf("session checker is required")
	}

	return &AuthMiddleware{
		verifier:       verifier,
		sessionChecker: sessionChecker,
	}, nil
}

// RequireAuth wraps an http.Handler with bearer token authentication and session validation.
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Authorization header is required.",
			)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" || strings.ContainsAny(parts[1], " \t\r\n") {
			writeProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Invalid authorization header format.",
			)
			return
		}

		tokenString := parts[1]

		claims, err := m.verifier.VerifyAccessToken(tokenString)
		if err != nil {
			writeProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Invalid or expired access token.",
			)
			return
		}

		if claims == nil || claims.UserID == uuid.Nil || claims.SessionID == uuid.Nil || claims.TokenID == uuid.Nil {
			writeProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Invalid access token claims.",
			)
			return
		}

		active, err := m.sessionChecker.IsActive(r.Context(), claims.SessionID)
		if err != nil {
			writeProblem(
				w,
				http.StatusServiceUnavailable,
				"Service Unavailable",
				"Authentication service is temporarily unavailable.",
			)
			return
		}

		if !active {
			writeProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Session is invalid, expired, or revoked.",
			)
			return
		}

		ctx := WithClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type problemDetails struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func writeProblem(
	w http.ResponseWriter,
	status int,
	title string,
	detail string,
) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(problemDetails{
		Type:   "https://orb.example.com/problems/" + titleToSlug(title),
		Title:  title,
		Status: status,
		Detail: detail,
	})
}

func titleToSlug(title string) string {
	switch title {
	case "Unauthorized":
		return "unauthorized"
	case "Forbidden":
		return "forbidden"
	case "Service Unavailable":
		return "service-unavailable"
	default:
		return "internal-error"
	}
}
