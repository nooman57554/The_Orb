package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

func TestAuthorizationHandler_Check_Allowed(t *testing.T) {
	authzRepo := newMockAuthzRepository()
	authzService, err := service.NewAuthorizationService(authzRepo)
	if err != nil {
		t.Fatalf("failed to create authorization service: %v", err)
	}

	h := handler.NewAuthorizationHandler(authzService)

	userID := uuid.New()
	tenantID := uuid.New()
	authzRepo.grantTenant(userID, tenantID, "user.read")

	principal := &identity.Principal{
		UserID:    userID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	body, _ := json.Marshal(map[string]any{
		"action":        "user.read",
		"resource_type": "user",
		"tenant_id":     tenantID.String(),
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/check", bytes.NewReader(body))
	req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
	rec := httptest.NewRecorder()

	h.Check(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Allowed bool `json:"allowed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed true, got false")
	}
}

func TestAuthorizationHandler_Check_Denied(t *testing.T) {
	authzRepo := newMockAuthzRepository()
	authzService, err := service.NewAuthorizationService(authzRepo)
	if err != nil {
		t.Fatalf("failed to create authorization service: %v", err)
	}

	h := handler.NewAuthorizationHandler(authzService)

	userID := uuid.New()
	tenantID := uuid.New()
	// No permissions granted

	principal := &identity.Principal{
		UserID:    userID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	body, _ := json.Marshal(map[string]any{
		"action":        "user.read",
		"resource_type": "user",
		"tenant_id":     tenantID.String(),
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/check", bytes.NewReader(body))
	req = req.WithContext(identity.WithPrincipal(req.Context(), principal))
	rec := httptest.NewRecorder()

	h.Check(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Allowed {
		t.Fatalf("expected allowed false, got true")
	}
}

func TestAuthorizationHandler_Check_Unauthenticated(t *testing.T) {
	authzRepo := newMockAuthzRepository()
	authzService, _ := service.NewAuthorizationService(authzRepo)
	h := handler.NewAuthorizationHandler(authzService)

	body, _ := json.Marshal(map[string]any{
		"action": "user.read",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/check", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.Check(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}
