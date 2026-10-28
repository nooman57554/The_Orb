package middleware

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

// Authorizer enforces route-level platform and tenant authorization policies.
type Authorizer struct {
	authzService *service.AuthorizationService
}

// NewAuthorizer creates a new route-level Authorizer.
func NewAuthorizer(authzService *service.AuthorizationService) (*Authorizer, error) {
	return &Authorizer{authzService: authzService}, nil
}

// RequirePlatform enforces that the caller holds the specified platform permission.
// Missing policies, unauthenticated principals, forbidden requests, and DB errors fail closed.
func (a *Authorizer) RequirePlatform(permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if permission == "" {
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "Route authorization policy is misconfigured: missing permission.")
			return
		}

		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || principal == nil || !principal.IsValid() {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}

		if err := a.authzService.AuthorizePlatform(r.Context(), principal, permission); err != nil {
			if errors.Is(err, service.ErrUnauthorized) {
				httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
				return
			}
			if errors.Is(err, service.ErrForbidden) {
				httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You do not have the required platform permission.")
				return
			}
			// Infrastructure errors fail closed with 500
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An authorization error occurred.")
			return
		}

		next(w, r)
	}
}

// RequireTenant enforces that the caller holds the specified tenant permission in the tenant
// identified by the route parameter name (e.g., "tenantID" or "id").
// Missing policies, malformed tenant IDs, unauthenticated principals, forbidden requests, and DB errors fail closed.
func (a *Authorizer) RequireTenant(tenantParam string, permission string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if permission == "" || tenantParam == "" {
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "Route authorization policy is misconfigured: missing parameters.")
			return
		}

		rawTenantID := r.PathValue(tenantParam)
		if rawTenantID == "" {
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID parameter is required.")
			return
		}

		tenantID, err := uuid.Parse(rawTenantID)
		if err != nil || tenantID == uuid.Nil {
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
			return
		}

		principal, ok := identity.PrincipalFromContext(r.Context())
		if !ok || principal == nil || !principal.IsValid() {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}

		if err := a.authzService.AuthorizeTenant(r.Context(), principal, tenantID, permission); err != nil {
			if errors.Is(err, service.ErrUnauthorized) {
				httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
				return
			}
			if errors.Is(err, service.ErrForbidden) {
				httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You do not have the required tenant permission.")
				return
			}
			// Infrastructure errors fail closed with 500
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An authorization error occurred.")
			return
		}

		next(w, r)
	}
}
