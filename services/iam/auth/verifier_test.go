package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/auth"
)

func TestNewJWTPrincipalVerifier_Validation(t *testing.T) {
	if _, err := auth.NewJWTPrincipalVerifier(nil); err == nil {
		t.Error("expected error when jwtManager is nil")
	}
}

func TestClaimsToPrincipal(t *testing.T) {
	userID := uuid.New()
	sessionID := uuid.New()
	tokenID := uuid.New()
	tenantID := uuid.New()

	t.Run("valid claims with tenant", func(t *testing.T) {
		claims := &auth.Claims{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   tokenID,
			TenantID:  &tenantID,
		}

		principal, err := auth.ClaimsToPrincipal(claims)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if principal.UserID != userID {
			t.Errorf("expected UserID %s, got %s", userID, principal.UserID)
		}
		if principal.SessionID != sessionID {
			t.Errorf("expected SessionID %s, got %s", sessionID, principal.SessionID)
		}
		if principal.TokenID != tokenID {
			t.Errorf("expected TokenID %s, got %s", tokenID, principal.TokenID)
		}
		if principal.TenantID == nil || *principal.TenantID != tenantID {
			t.Errorf("expected TenantID %s, got %v", tenantID, principal.TenantID)
		}
	})

	t.Run("valid claims without tenant", func(t *testing.T) {
		claims := &auth.Claims{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   tokenID,
		}

		principal, err := auth.ClaimsToPrincipal(claims)
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if principal.TenantID != nil {
			t.Errorf("expected nil TenantID, got %v", principal.TenantID)
		}
	})

	t.Run("nil claims", func(t *testing.T) {
		if _, err := auth.ClaimsToPrincipal(nil); err == nil {
			t.Error("expected error for nil claims")
		}
	})

	t.Run("invalid claims with nil UserID", func(t *testing.T) {
		claims := &auth.Claims{
			UserID:    uuid.Nil,
			SessionID: sessionID,
			TokenID:   tokenID,
		}
		if _, err := auth.ClaimsToPrincipal(claims); err == nil {
			t.Error("expected error for claims with nil UserID")
		}
	})
}

func TestJWTPrincipalVerifier_VerifyAccessToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	keyID := "test-key-1"
	issuer := "orb-iam-test"
	audience := "orb-platform-test"

	manager, err := auth.NewJWTManager(
		priv,
		keyID,
		map[string]ed25519.PublicKey{keyID: pub},
		issuer,
		audience,
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create JWTManager: %v", err)
	}

	verifier, err := auth.NewJWTPrincipalVerifier(manager)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}

	userID := uuid.New()
	sessionID := uuid.New()
	tokenID := uuid.New()

	tokenString, err := manager.CreateAccessToken(auth.Claims{
		UserID:    userID,
		SessionID: sessionID,
		TokenID:   tokenID,
	})
	if err != nil {
		t.Fatalf("create access token: %v", err)
	}

	t.Run("valid token verification", func(t *testing.T) {
		principal, err := verifier.VerifyAccessToken(tokenString)
		if err != nil {
			t.Fatalf("expected valid token verification, got error: %v", err)
		}
		if principal.UserID != userID {
			t.Errorf("expected UserID %s, got %s", userID, principal.UserID)
		}
		if principal.SessionID != sessionID {
			t.Errorf("expected SessionID %s, got %s", sessionID, principal.SessionID)
		}
		if principal.TokenID != tokenID {
			t.Errorf("expected TokenID %s, got %s", tokenID, principal.TokenID)
		}
	})

	t.Run("invalid token string", func(t *testing.T) {
		if _, err := verifier.VerifyAccessToken("not.a.valid.jwt"); err == nil {
			t.Error("expected error for invalid token string")
		}
	})
}
