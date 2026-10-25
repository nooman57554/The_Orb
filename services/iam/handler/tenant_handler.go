package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type TenantHandler struct {
	tenantRepo   repository.TenantRepository
	authzService *service.AuthorizationService
}

func NewTenantHandler(
	tenantRepo repository.TenantRepository,
	authzService *service.AuthorizationService,
) *TenantHandler {
	return &TenantHandler{
		tenantRepo:   tenantRepo,
		authzService: authzService,
	}
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

	writeJSON(w, http.StatusOK, tenantResponse{
		ID:        tenant.ID.String(),
		Name:      tenant.Name,
		Slug:      tenant.Slug,
		Status:    tenant.Status,
		CreatedAt: tenant.CreatedAt.Format(time.RFC3339),
		UpdatedAt: tenant.UpdatedAt.Format(time.RFC3339),
	})
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

	writeJSON(w, http.StatusOK, tenantResponse{
		ID:        tenant.ID.String(),
		Name:      tenant.Name,
		Slug:      tenant.Slug,
		Status:    tenant.Status,
		CreatedAt: tenant.CreatedAt.Format(time.RFC3339),
		UpdatedAt: tenant.UpdatedAt.Format(time.RFC3339),
	})
}
