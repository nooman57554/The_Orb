package identity_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

func TestPrincipal_IsValid_And_Validate(t *testing.T) {
	validUserID := uuid.New()
	validSessionID := uuid.New()
	validTokenID := uuid.New()
	validTenantID := uuid.New()

	tests := []struct {
		name      string
		principal *identity.Principal
		wantValid bool
	}{
		{
			name: "valid without tenant",
			principal: &identity.Principal{
				UserID:    validUserID,
				SessionID: validSessionID,
				TokenID:   validTokenID,
			},
			wantValid: true,
		},
		{
			name: "valid with tenant",
			principal: &identity.Principal{
				UserID:    validUserID,
				SessionID: validSessionID,
				TokenID:   validTokenID,
				TenantID:  &validTenantID,
			},
			wantValid: true,
		},
		{
			name:      "nil principal",
			principal: nil,
			wantValid: false,
		},
		{
			name: "missing user ID",
			principal: &identity.Principal{
				UserID:    uuid.Nil,
				SessionID: validSessionID,
				TokenID:   validTokenID,
			},
			wantValid: false,
		},
		{
			name: "missing session ID",
			principal: &identity.Principal{
				UserID:    validUserID,
				SessionID: uuid.Nil,
				TokenID:   validTokenID,
			},
			wantValid: false,
		},
		{
			name: "missing token ID",
			principal: &identity.Principal{
				UserID:    validUserID,
				SessionID: validSessionID,
				TokenID:   uuid.Nil,
			},
			wantValid: false,
		},
		{
			name: "nil tenant ID pointer value",
			principal: func() *identity.Principal {
				nilUUID := uuid.Nil
				return &identity.Principal{
					UserID:    validUserID,
					SessionID: validSessionID,
					TokenID:   validTokenID,
					TenantID:  &nilUUID,
				}
			}(),
			wantValid: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotValid := tc.principal.IsValid()
			if gotValid != tc.wantValid {
				t.Errorf("IsValid() = %v, want %v", gotValid, tc.wantValid)
			}

			err := tc.principal.Validate()
			if tc.wantValid && err != nil {
				t.Errorf("Validate() expected nil error, got: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Errorf("Validate() expected error for invalid principal, got nil")
			}
		})
	}
}

func TestContextRoundTrip(t *testing.T) {
	principal := &identity.Principal{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	ctx := context.Background()
	ctx = identity.WithPrincipal(ctx, principal)

	retrieved, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		t.Fatal("expected PrincipalFromContext to return ok = true")
	}
	if retrieved == nil {
		t.Fatal("expected non-nil principal")
	}
	if retrieved.UserID != principal.UserID {
		t.Errorf("expected UserID %s, got %s", principal.UserID, retrieved.UserID)
	}
	if retrieved.SessionID != principal.SessionID {
		t.Errorf("expected SessionID %s, got %s", principal.SessionID, retrieved.SessionID)
	}
	if retrieved.TokenID != principal.TokenID {
		t.Errorf("expected TokenID %s, got %s", principal.TokenID, retrieved.TokenID)
	}
}

func TestPrincipalFromContext_MissingOrNil(t *testing.T) {
	// 1. Nil context
	if p, ok := identity.PrincipalFromContext(nil); ok || p != nil {
		t.Errorf("expected nil context to return nil, false; got %v, %v", p, ok)
	}

	// 2. Empty context without principal
	ctx := context.Background()
	if p, ok := identity.PrincipalFromContext(ctx); ok || p != nil {
		t.Errorf("expected empty context to return nil, false; got %v, %v", p, ok)
	}

	// 3. Context with nil principal pointer
	ctx = identity.WithPrincipal(ctx, nil)
	if p, ok := identity.PrincipalFromContext(ctx); ok || p != nil {
		t.Errorf("expected context with nil principal to return nil, false; got %v, %v", p, ok)
	}

	// 4. Context with invalid principal (e.g. nil UserID)
	invalidPrincipal := &identity.Principal{
		UserID:    uuid.Nil,
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}
	ctx = identity.WithPrincipal(ctx, invalidPrincipal)
	if p, ok := identity.PrincipalFromContext(ctx); ok || p != nil {
		t.Errorf("expected context with invalid principal to return nil, false; got %v, %v", p, ok)
	}
}

func TestNoAccidentalContextKeyCollision(t *testing.T) {
	principal := &identity.Principal{
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		TokenID:   uuid.New(),
	}

	// Someone attempts to set a string key "principal"
	ctx := context.WithValue(context.Background(), "principal", principal)
	ctx = context.WithValue(ctx, "identity", principal)

	// identity.PrincipalFromContext must not find it because it uses a private type
	if p, ok := identity.PrincipalFromContext(ctx); ok || p != nil {
		t.Errorf("expected no collision with string context key, but found %v", p)
	}
}
