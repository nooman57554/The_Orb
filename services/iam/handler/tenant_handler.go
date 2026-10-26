package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type TenantHandler struct {
	tenantRepo    repository.TenantRepository
	tenantService *service.TenantService
	authzService  *service.AuthorizationService
}

func NewTenantHandler(
	tenantRepo repository.TenantRepository,
	authzService *service.AuthorizationService,
	tenantService ...*service.TenantService,
) *TenantHandler {
	var ts *service.TenantService
	if len(tenantService) > 0 && tenantService[0] != nil {
		ts = tenantService[0]
	} else if tenantRepo != nil {
		ts, _ = service.NewTenantService(tenantRepo)
	}

	return &TenantHandler{
		tenantRepo:    tenantRepo,
		tenantService: ts,
		authzService:  authzService,
	}
}

type createTenantRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type updateTenantRequest struct {
	Name string `json:"name"`
}

type tenantResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func formatTenant(t *model.Tenant) tenantResponse {
	return tenantResponse{
		ID:        t.ID.String(),
		Name:      t.Name,
		Slug:      t.Slug,
		Status:    t.Status,
		CreatedAt: t.CreatedAt.Format(time.RFC3339),
		UpdatedAt: t.UpdatedAt.Format(time.RFC3339),
	}
}

func (h *TenantHandler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	if err := h.authzService.AuthorizePlatform(r.Context(), principal, "tenant.create"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to create tenants.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	var req createTenantRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Request body must contain valid JSON.")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant name cannot be empty.")
		return
	}
	slug := strings.TrimSpace(req.Slug)
	if slug == "" {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant slug cannot be empty.")
		return
	}

	tenant, err := h.tenantService.CreateTenant(r.Context(), name, slug)
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrDuplicateSlug):
			httpx.WriteProblem(w, http.StatusConflict, "Tenant Already Exists", "A tenant with this slug already exists.")
		case errors.Is(err, service.ErrInvalidTenantName):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant name cannot be empty.")
		case errors.Is(err, service.ErrInvalidTenantSlug):
			httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant slug cannot be empty.")
		default:
			httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		}
		return
	}

	writeJSON(w, http.StatusCreated, formatTenant(tenant))
}

func (h *TenantHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	if err := h.authzService.AuthorizePlatform(r.Context(), principal, "tenant.read"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to list tenants.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	offset, limit := parsePagination(r)
	page := (offset / limit) + 1

	tenants, total, err := h.tenantService.ListTenants(r.Context(), offset, limit)
	if err != nil {
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	items := make([]tenantResponse, len(tenants))
	for i := range tenants {
		items[i] = formatTenant(&tenants[i])
	}

	writeJSON(w, http.StatusOK, struct {
		Tenants []tenantResponse `json:"tenants"`
		Total   int              `json:"total"`
		Page    int              `json:"page"`
		Limit   int              `json:"limit"`
	}{
		Tenants: items,
		Total:   total,
		Page:    page,
		Limit:   limit,
	})
}

func (h *TenantHandler) GetTenant(w http.ResponseWriter, r *http.Request) {
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

	tenantID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Tenant ID must be a valid UUID.",
		)
		return
	}

	if err := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "tenant.read"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Authentication is required.",
			)
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(
				w,
				http.StatusForbidden,
				"Forbidden",
				"You are not authorized to access this tenant.",
			)
			return
		}
		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	tenant, err := h.tenantRepo.GetByID(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httpx.WriteProblem(
				w,
				http.StatusNotFound,
				"Tenant Not Found",
				"The requested tenant was not found.",
			)
			return
		}
		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	writeJSON(w, http.StatusOK, formatTenant(tenant))
}

func (h *TenantHandler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
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

	tenantID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Tenant ID must be a valid UUID.",
		)
		return
	}

	if err := h.authzService.AuthorizeTenant(r.Context(), principal, tenantID, "tenant.update"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Authentication is required.",
			)
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(
				w,
				http.StatusForbidden,
				"Forbidden",
				"You are not authorized to access this tenant.",
			)
			return
		}
		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	var req updateTenantRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Request body must contain valid JSON.",
		)
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Tenant name cannot be empty.",
		)
		return
	}

	tenant, err := h.tenantRepo.GetByID(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httpx.WriteProblem(
				w,
				http.StatusNotFound,
				"Tenant Not Found",
				"The requested tenant was not found.",
			)
			return
		}
		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	tenant.Name = name
	if err := h.tenantRepo.Update(r.Context(), tenant); err != nil {
		httpx.WriteProblem(
			w,
			http.StatusInternalServerError,
			"Internal Server Error",
			"An unexpected error occurred.",
		)
		return
	}

	writeJSON(w, http.StatusOK, formatTenant(tenant))
}

func (h *TenantHandler) DeactivateTenant(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}

	if err := h.authzService.AuthorizePlatform(r.Context(), principal, "tenant.deactivate"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to deactivate tenants.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	if err := h.tenantService.DeactivateTenant(r.Context(), tenantID); err != nil {
		if errors.Is(err, service.ErrTenantNotFound) {
			httpx.WriteProblem(w, http.StatusNotFound, "Tenant Not Found", "The requested tenant was not found.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *TenantHandler) ReactivateTenant(w http.ResponseWriter, r *http.Request) {
	principal, ok := identity.PrincipalFromContext(r.Context())
	if !ok {
		httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
		return
	}

	tenantID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, http.StatusBadRequest, "Invalid Request", "Tenant ID must be a valid UUID.")
		return
	}

	if err := h.authzService.AuthorizePlatform(r.Context(), principal, "tenant.reactivate"); err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			httpx.WriteProblem(w, http.StatusUnauthorized, "Unauthorized", "Authentication is required.")
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			httpx.WriteProblem(w, http.StatusForbidden, "Forbidden", "You are not authorized to reactivate tenants.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	if err := h.tenantService.ReactivateTenant(r.Context(), tenantID); err != nil {
		if errors.Is(err, service.ErrTenantNotFound) {
			httpx.WriteProblem(w, http.StatusNotFound, "Tenant Not Found", "The requested tenant was not found.")
			return
		}
		httpx.WriteProblem(w, http.StatusInternalServerError, "Internal Server Error", "An unexpected error occurred.")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
