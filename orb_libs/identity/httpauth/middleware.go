package httpauth

import (
	"context"
	"fmt"
	"net/http"
	"path"
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
// Requests are protected by default unless matching an explicitly configured public route.
type BearerMiddleware struct {
	verifier       identity.TokenVerifier
	sessionChecker SessionChecker
	publicRoutes   map[string]struct{}
}

// NewBearerMiddleware creates a new BearerMiddleware instance.
// Verifier is required. SessionChecker is optional (pass nil to disable session checks).
// publicRoutes is an optional list of routes formatted as "METHOD /path" (e.g. "POST /v1/auth/login").
func NewBearerMiddleware(
	verifier identity.TokenVerifier,
	sessionChecker SessionChecker,
	publicRoutes ...string,
) (*BearerMiddleware, error) {
	if verifier == nil {
		return nil, fmt.Errorf("token verifier is required")
	}

	routes := make(map[string]struct{}, len(publicRoutes))
	for _, r := range publicRoutes {
		norm := normalizeRouteKey(r)
		if norm != "" {
			routes[norm] = struct{}{}
		}
	}

	return &BearerMiddleware{
		verifier:       verifier,
		sessionChecker: sessionChecker,
		publicRoutes:   routes,
	}, nil
}

// AllowPublic registers an explicit public route by HTTP method and exact path.
// Lifecycle: AllowPublic must only be called during server setup and initialization,
// before concurrent request handling begins. It is not thread-safe for concurrent
// modification once the server starts processing requests.
func (m *BearerMiddleware) AllowPublic(method, pathStr string) *BearerMiddleware {
	if m.publicRoutes == nil {
		m.publicRoutes = make(map[string]struct{})
	}
	cleanPath := path.Clean(strings.TrimSpace(pathStr))
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	key := strings.ToUpper(strings.TrimSpace(method)) + " " + cleanPath
	m.publicRoutes[key] = struct{}{}
	return m
}

func (m *BearerMiddleware) isPublic(method, reqPath string) bool {
	if len(m.publicRoutes) == 0 {
		return false
	}
	cleanPath := path.Clean(reqPath)
	key := strings.ToUpper(strings.TrimSpace(method)) + " " + cleanPath
	_, ok := m.publicRoutes[key]
	return ok
}

func normalizeRouteKey(route string) string {
	parts := strings.Fields(route)
	if len(parts) == 2 {
		return strings.ToUpper(parts[0]) + " " + path.Clean(parts[1])
	}
	return ""
}

// Require wraps an http.Handler with default bearer-token authentication.
// If the incoming request matches an explicitly registered public route, authentication
// is bypassed and the next handler is called directly without injecting a principal.
// All other requests require a valid bearer token and active session.
func (m *BearerMiddleware) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.isPublic(r.Method, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

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
