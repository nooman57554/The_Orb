package handler

import (
	"net/http"
	"time"

	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type PermissionHandler struct {
	roleService  *service.RoleService
	authzService *service.AuthorizationService
}

func NewPermissionHandler(
	roleService *service.RoleService,
	authzService *service.AuthorizationService,
) *PermissionHandler {
	return &PermissionHandler{
		roleService:  roleService,
		authzService: authzService,
	}
}

type permissionItemResponse struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	TenantEligible bool   `json:"tenant_eligible"`
	CreatedAt      string `json:"created_at"`
}

type listPermissionsResponse struct {
	Permissions []permissionItemResponse `json:"permissions"`
}

func (h *PermissionHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
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

	// Authorize permission catalog listing
	tenantIDStr := r.URL.Query().Get("tenant_id")
	var authReq authorization.AuthorizationRequest
	if tenantIDStr != "" {
		tenantID, parseErr := parseUUID(tenantIDStr)
		if parseErr != nil {
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "tenant_id must be a valid UUID.")
			return
		}
		authReq = authorization.AuthorizationRequest{
			Principal:  principal,
			Permission: authorization.PermTenantPermissionRead,
			TenantID:   tenantID.String(),
		}
	} else {
		authReq = authorization.AuthorizationRequest{
			Principal:  principal,
			Permission: authorization.PermPlatformRoleRead,
		}
	}

	decision, err := h.authzService.Authorize(r.Context(), authReq)
	if err != nil {
		httpx.WriteProblem(
			w,
			http.StatusServiceUnavailable,
			"Service Unavailable",
			"Authorization policy is temporarily unavailable.",
		)
		return
	}

	if !decision.Allowed {
		// If platform role read was denied and no tenant_id was specified, but caller is a tenant member
		// checking permission catalog, evaluate if caller holds tenant permission.read on their principal tenant
		allowed := false
		if tenantIDStr == "" && principal.TenantID != nil {
			fallbackReq := authorization.AuthorizationRequest{
				Principal:  principal,
				Permission: authorization.PermTenantPermissionRead,
				TenantID:   principal.TenantID.String(),
			}
			if fbDec, fbErr := h.authzService.Authorize(r.Context(), fallbackReq); fbErr == nil && fbDec.Allowed {
				allowed = true
			}
		}

		if !allowed {
			httpx.WriteProblem(
				w,
				http.StatusForbidden,
				"Forbidden",
				"You are not authorized to view the permission catalog.",
			)
			return
		}
	}

	perms, err := h.roleService.ListPermissions(r.Context())
	if err != nil {
		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	items := make([]permissionItemResponse, len(perms))
	for i, p := range perms {
		items[i] = permissionItemResponse{
			ID:             p.ID.String(),
			Name:           p.Name,
			Description:    p.Description,
			TenantEligible: p.Scope == "tenant",
			CreatedAt:      p.CreatedAt.Format(time.RFC3339),
		}
	}

	writeJSON(w, http.StatusOK, listPermissionsResponse{
		Permissions: items,
	})
}
