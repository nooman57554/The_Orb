package authorization

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

// Authorizer enforces access control on HTTP routes using the shared authorization Engine.
type Authorizer struct {
	engine Engine
}

// NewAuthorizer creates a new route Authorizer backed by an authorization Engine.
func NewAuthorizer(engine Engine) (*Authorizer, error) {
	if engine == nil {
		return nil, fmt.Errorf("authorization engine is required")
	}
	return &Authorizer{engine: engine}, nil
}

// Engine returns the underlying authorization engine.
func (a *Authorizer) Engine() Engine {
	return a.engine
}

// Require protects an http.HandlerFunc with the specified canonical permission and optional resolvers.
// Resolvers may implement TenantResolver (e.g. RouteParam("tenantID")) and/or ResourceResolver (e.g. ResourceRouteParam("user", "id")).
// If no TenantResolver is supplied for a tenant-scoped permission, FromContext() is used as fallback.
func (a *Authorizer) Require(permission string, resolvers ...any) func(http.HandlerFunc) http.HandlerFunc {
	perm := strings.TrimSpace(permission)

	var tenantResolver TenantResolver
	var resourceResolver ResourceResolver

	for _, res := range resolvers {
		switch r := res.(type) {
		case TenantResolver:
			tenantResolver = r
		case ResourceResolver:
			resourceResolver = r
		}
	}

	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if perm == "" {
				httpx.WriteProblem(
					w,
					http.StatusInternalServerError,
					"Internal Server Error",
					"Route authorization policy is misconfigured: missing permission.",
				)
				return
			}

			// 1. Obtain verified principal from context
			principal, ok := identity.PrincipalFromContext(r.Context())
			if !ok || principal == nil || !principal.IsValid() {
				httpx.WriteProblem(
					w,
					http.StatusUnauthorized,
					"Unauthorized",
					"Authentication is required.",
				)
				return
			}

			// 2. Resolve scope from canonical catalog
			scope, known := ScopeOf(perm)
			if !known {
				httpx.WriteProblem(
					w,
					http.StatusInternalServerError,
					"Internal Server Error",
					fmt.Sprintf("Route authorization policy is misconfigured: unknown permission %q.", perm),
				)
				return
			}

			// 3. Resolve tenant ID if tenant-scoped
			var tenantID string
			if scope == ScopeTenant {
				var resolveErr error
				if tenantResolver != nil {
					tenantID, resolveErr = tenantResolver.ResolveTenant(r)
				} else {
					tenantID, resolveErr = FromContext().ResolveTenant(r)
				}

				if resolveErr != nil {
					httpx.WriteProblem(
						w,
						http.StatusBadRequest,
						"Invalid Request",
						fmt.Sprintf("Tenant scope resolution failed: %v", resolveErr),
					)
					return
				}
			}

			// 4. Resolve resource if resourceResolver provided
			var resType, resID string
			if resourceResolver != nil {
				var resErr error
				resType, resID, resErr = resourceResolver.ResolveResource(r)
				if resErr != nil {
					httpx.WriteProblem(
						w,
						http.StatusBadRequest,
						"Invalid Request",
						fmt.Sprintf("Resource scope resolution failed: %v", resErr),
					)
					return
				}
			}

			// 5. Construct AuthorizationRequest
			req := AuthorizationRequest{
				Principal:    principal,
				Permission:   perm,
				TenantID:     tenantID,
				ResourceType: resType,
				ResourceID:   resID,
			}

			// 6. Evaluate authorization against local engine
			decision, err := a.engine.Authorize(r.Context(), req)
			if err != nil {
				if errors.Is(err, ErrPolicyUnavailable) || errors.Is(err, ErrPolicyStale) {
					httpx.WriteProblem(
						w,
						http.StatusServiceUnavailable,
						"Service Unavailable",
						"Authorization policy is temporarily unavailable.",
					)
					return
				}

				httpx.WriteProblem(
					w,
					http.StatusInternalServerError,
					"Internal Server Error",
					"An authorization error occurred.",
				)
				return
			}

			if !decision.Allowed {
				switch decision.Reason {
				case ReasonUnauthenticated:
					httpx.WriteProblem(
						w,
						http.StatusUnauthorized,
						"Unauthorized",
						"Authentication is required.",
					)
				case ReasonUserInactive:
					httpx.WriteProblem(
						w,
						http.StatusForbidden,
						"Forbidden",
						"The authenticated user is inactive.",
					)
				case ReasonTenantInactive:
					httpx.WriteProblem(
						w,
						http.StatusForbidden,
						"Forbidden",
						"The specified tenant is inactive or suspended.",
					)
				default:
					httpx.WriteProblem(
						w,
						http.StatusForbidden,
						"Forbidden",
						"You do not have the required permissions to perform this action.",
					)
				}
				return
			}

			// Authorized: proceed to next handler
			next(w, r)
		}
	}
}

// RequireHandler wraps a standard http.Handler with the common authorization policy.
func (a *Authorizer) RequireHandler(permission string, resolvers ...any) func(http.Handler) http.Handler {
	wrapper := a.Require(permission, resolvers...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(wrapper(next.ServeHTTP))
	}
}
