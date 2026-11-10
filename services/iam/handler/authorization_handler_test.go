package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/authorization"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
	"github.com/nooman57554/The_Orb/services/iam/handler"
)

func TestAuthorizationHandler_Check_Allowed(t *testing.T) {
	holder := authorization.NewSnapshotHolder()
	engine := authorization.NewLocalEngine(holder)

	h := handler.NewAuthorizationHandler(engine)

	userID := uuid.New()
	tenantID := uuid.New()
	roleID := uuid.New()

	snap := &authorization.PolicySnapshot{
		Version:   1,
		CreatedAt: time.Now(),
		Users: map[string]authorization.UserPolicy{
			userID.String(): {Active: true},
		},
		TenantAssignments: map[string]map[string]string{
			userID.String(): {tenantID.String(): roleID.String()},
		},
		Roles: map[string]authorization.RolePolicy{
			roleID.String(): {
				ID:          roleID.String(),
				Scope:       authorization.RoleScopeSystemTenant,
				Permissions: []string{"tenant.user.read"},
			},
		},
		Permissions: map[string]authorization.PermissionDefinition{
			"tenant.user.read": {Name: "tenant.user.read", Scope: authorization.ScopeTenant},
		},
	}
	if err := holder.Set(snap); err != nil {
		t.Fatalf("failed to set snapshot: %v", err)
	}

	principal := &identity.Principal{
		UserID:    userID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	body, _ := json.Marshal(map[string]any{
		"action":        "tenant.user.read",
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
	holder := authorization.NewSnapshotHolder()
	engine := authorization.NewLocalEngine(holder)

	h := handler.NewAuthorizationHandler(engine)

	userID := uuid.New()
	tenantID := uuid.New()

	snap := &authorization.PolicySnapshot{
		Version:             1,
		CreatedAt:           time.Now(),
		Users:               map[string]authorization.UserPolicy{userID.String(): {Active: true}},
		PlatformAssignments: map[string]string{},
		TenantAssignments:   map[string]map[string]string{},
		Roles:               map[string]authorization.RolePolicy{},
		Permissions: map[string]authorization.PermissionDefinition{
			"tenant.user.read": {Name: "tenant.user.read", Scope: authorization.ScopeTenant},
		},
	}
	if err := holder.Set(snap); err != nil {
		t.Fatalf("failed to set snapshot: %v", err)
	}

	principal := &identity.Principal{
		UserID:    userID,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	body, _ := json.Marshal(map[string]any{
		"action":        "tenant.user.read",
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
	holder := authorization.NewSnapshotHolder()
	engine := authorization.NewLocalEngine(holder)
	h := handler.NewAuthorizationHandler(engine)

	body, _ := json.Marshal(map[string]any{
		"action": authorization.PermTenantUserRead,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/authorization/check", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.Check(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
}
