package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type PermissionHandler struct {
	permRepo     repository.PermissionRepository
	authzService *service.AuthorizationService
}

func NewPermissionHandler(
	permRepo repository.PermissionRepository,
	authzService *service.AuthorizationService,
) *PermissionHandler {
	return &PermissionHandler{
		permRepo:     permRepo,
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
	if !ok {
		httpx.WriteProblem(
			w,
			http.StatusUnauthorized,
			"Unauthorized",
			"Authentication is required.",
		)
		return
	}

	// Permission catalog read is permitted with platform permission.read OR any tenant permission.read
	err := h.authzService.AuthorizePlatform(r.Context(), principal, "permission.read")
	if err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		// If not platform, check if caller holds permission.read on their tenant if tenant_id query is provided
		tenantIDStr := r.URL.Query().Get("tenant_id")
		tenantAuthOk := false
		if tenantIDStr != "" {
			if tenantID, parseErr := parseUUID(tenantIDStr); parseErr == nil {
				if tErr := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "permission.read"); tErr == nil {
					tenantAuthOk = true
				}
			}
		}

		if !tenantAuthOk {
			httpx.WriteProblem(
				w,
				http.StatusForbidden,
				"Forbidden",
				"You are not authorized to view the permission catalog.",
			)
			return
		}
	}

	perms, err := h.permRepo.ListAll(r.Context())
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
		_, eligible := service.AllowedTenantPermissions[p.Name]
		items[i] = permissionItemResponse{
			ID:             p.ID.String(),
			Name:           p.Name,
			Description:    p.Description,
			TenantEligible: eligible,
			CreatedAt:      p.CreatedAt.Format(time.RFC3339),
		}
	}

	writeJSON(w, http.StatusOK, listPermissionsResponse{
		Permissions: items,
	})
}
