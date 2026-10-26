package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

type AuthorizationHandler struct {
	authzService *service.AuthorizationService
}

func NewAuthorizationHandler(authzService *service.AuthorizationService) *AuthorizationHandler {
	return &AuthorizationHandler{
		authzService: authzService,
	}
}

type checkAuthorizationRequest struct {
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	TenantID     string `json:"tenant_id"`
}

type checkAuthorizationResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

func (h *AuthorizationHandler) Check(w http.ResponseWriter, r *http.Request) {
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

	var req checkAuthorizationRequest
	if err := decodeJSON(w, r, &req); err != nil {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Request body must contain valid JSON.",
		)
		return
	}

	action := strings.TrimSpace(req.Action)
	if action == "" {
		httpx.WriteProblem(
			w,
			http.StatusBadRequest,
			"Invalid Request",
			"Action is required.",
		)
		return
	}

	var tenantID uuid.UUID
	if strings.TrimSpace(req.TenantID) != "" {
		var err error
		tenantID, err = uuid.Parse(strings.TrimSpace(req.TenantID))
		if err != nil {
			httpx.WriteProblem(
				w,
				http.StatusBadRequest,
				"Invalid Request",
				"tenant_id must be a valid UUID.",
			)
			return
		}
	}

	authReq := service.AuthorizationRequest{
		Action:       action,
		ResourceType: strings.TrimSpace(req.ResourceType),
		ResourceID:   strings.TrimSpace(req.ResourceID),
		TenantID:     tenantID,
	}

	err := h.authzService.Authorize(r.Context(), principal, authReq)
	if err != nil {
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
			writeJSON(w, http.StatusOK, checkAuthorizationResponse{
				Allowed: false,
				Reason:  "insufficient permissions",
			})
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

	writeJSON(w, http.StatusOK, checkAuthorizationResponse{
		Allowed: true,
	})
}
