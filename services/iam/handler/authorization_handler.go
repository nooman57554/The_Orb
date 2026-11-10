package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/httpx"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

type AuthorizationHandler struct {
	authzEngine authorization.Engine
}

func NewAuthorizationHandler(authzEngine authorization.Engine) *AuthorizationHandler {
	return &AuthorizationHandler{
		authzEngine: authzEngine,
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

// Check evaluates an authorization check request against the canonical authorization policy.
// This endpoint is authenticated and allows callers to verify authorization decisions.
func (h *AuthorizationHandler) Check(w http.ResponseWriter, r *http.Request) {
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

	var tenantIDStr string
	if strings.TrimSpace(req.TenantID) != "" {
		tenantID, err := uuid.Parse(strings.TrimSpace(req.TenantID))
		if err != nil || tenantID == uuid.Nil {
			httpx.WriteProblem(
				w,
				http.StatusBadRequest,
				"Invalid Request",
				"tenant_id must be a valid UUID.",
			)
			return
		}
		tenantIDStr = tenantID.String()
	}

	authReq := authorization.AuthorizationRequest{
		Principal:    principal,
		Permission:   action,
		ResourceType: strings.TrimSpace(req.ResourceType),
		ResourceID:   strings.TrimSpace(req.ResourceID),
		TenantID:     tenantIDStr,
	}

	decision, err := h.authzEngine.Authorize(r.Context(), authReq)
	if err != nil {
		if errors.Is(err, authorization.ErrPolicyUnavailable) || errors.Is(err, authorization.ErrPolicyStale) {
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
			"An unexpected error occurred.",
		)
		return
	}

	if !decision.Allowed {
		writeJSON(w, http.StatusOK, checkAuthorizationResponse{
			Allowed: false,
			Reason:  string(decision.Reason),
		})
		return
	}

	writeJSON(w, http.StatusOK, checkAuthorizationResponse{
		Allowed: true,
		Reason:  string(decision.Reason),
	})
}
