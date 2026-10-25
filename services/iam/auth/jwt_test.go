package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity/jwtverify"
	"github.com/nooman57554/The_Orb/services/iam/auth"
)

func generateEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return pub, priv
}

func TestNewJWTManager_Validation(t *testing.T) {
	_, priv := generateEd25519(t)

	tests := []struct {
		name        string
		privKey     ed25519.PrivateKey
		activeKeyID string
		issuer      string
		audience    string
		ttl         time.Duration
		wantErr     bool
	}{
		{
			name:        "valid parameters",
			privKey:     priv,
			activeKeyID: "key-1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     false,
		},
		{
			name:        "invalid private key size",
			privKey:     ed25519.PrivateKey([]byte("too-short")),
			activeKeyID: "key-1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "empty active key id",
			privKey:     priv,
			activeKeyID: "",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "dot active key id",
			privKey:     priv,
			activeKeyID: ".",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "dot dot active key id",
			privKey:     priv,
			activeKeyID: "..",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "active key id with slash",
			privKey:     priv,
			activeKeyID: "keys/key-1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "active key id with backslash",
			privKey:     priv,
			activeKeyID: "keys\\key-1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "active key id with space",
			privKey:     priv,
			activeKeyID: "key 1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "active key id with colon",
			privKey:     priv,
			activeKeyID: "key:1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "active key id with control char",
			privKey:     priv,
			activeKeyID: "key\x001",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "valid complex active key id",
			privKey:     priv,
			activeKeyID: "key_2026-01.v1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     false,
		},
		{
			name:        "empty issuer",
			privKey:     priv,
			activeKeyID: "key-1",
			issuer:      "",
			audience:    "orb-platform",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "empty audience",
			privKey:     priv,
			activeKeyID: "key-1",
			issuer:      "orb-iam",
			audience:    "",
			ttl:         15 * time.Minute,
			wantErr:     true,
		},
		{
			name:        "zero ttl",
			privKey:     priv,
			activeKeyID: "key-1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         0,
			wantErr:     true,
		},
		{
			name:        "negative ttl",
			privKey:     priv,
			activeKeyID: "key-1",
			issuer:      "orb-iam",
			audience:    "orb-platform",
			ttl:         -5 * time.Minute,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := auth.NewJWTManager(
				tt.privKey,
				tt.activeKeyID,
				tt.issuer,
				tt.audience,
				tt.ttl,
			)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewJWTManager() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && mgr == nil {
				t.Fatal("expected non-nil JWTManager")
			}
		})
	}
}

func TestJWTManager_CreateAccessToken(t *testing.T) {
	pub, priv := generateEd25519(t)
	keyID := "test-key-01"
	issuer := "orb-iam-test"
	audience := "orb-platform-test"
	ttl := 15 * time.Minute

	mgr, err := auth.NewJWTManager(priv, keyID, issuer, audience, ttl)
	if err != nil {
		t.Fatalf("initialize JWTManager: %v", err)
	}

	verifier, err := jwtverify.NewVerifier(
		map[string]ed25519.PublicKey{keyID: pub},
		issuer,
		audience,
	)
	if err != nil {
		t.Fatalf("initialize Verifier: %v", err)
	}

	t.Run("valid claims with tenant and token id", func(t *testing.T) {
		userID := uuid.New()
		sessionID := uuid.New()
		tokenID := uuid.New()
		tenantID := uuid.New()

		tokenString, err := mgr.CreateAccessToken(auth.Claims{
			UserID:    userID,
			SessionID: sessionID,
			TokenID:   tokenID,
			TenantID:  &tenantID,
		})
		if err != nil {
			t.Fatalf("CreateAccessToken() error = %v", err)
		}

		// Verify using shared verifier
		principal, err := verifier.VerifyAccessToken(tokenString)
		if err != nil {
			t.Fatalf("VerifyAccessToken() error = %v", err)
		}
		if principal.UserID != userID {
			t.Errorf("UserID = %v, want %v", principal.UserID, userID)
		}
		if principal.SessionID != sessionID {
			t.Errorf("SessionID = %v, want %v", principal.SessionID, sessionID)
		}
		if principal.TokenID != tokenID {
			t.Errorf("TokenID = %v, want %v", principal.TokenID, tokenID)
		}
		if principal.TenantID == nil || *principal.TenantID != tenantID {
			t.Errorf("TenantID = %v, want %v", principal.TenantID, tenantID)
		}

		// Inspect raw claims format
		parsed, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("parse unverified token: %v", err)
		}
		if parsed.Header["kid"] != keyID {
			t.Errorf("header kid = %v, want %v", parsed.Header["kid"], keyID)
		}
		if parsed.Header["alg"] != "EdDSA" {
			t.Errorf("header alg = %v, want EdDSA", parsed.Header["alg"])
		}
	})

	t.Run("valid claims without tenant and auto-generated token id", func(t *testing.T) {
		userID := uuid.New()
		sessionID := uuid.New()

		tokenString, err := mgr.CreateAccessToken(auth.Claims{
			UserID:    userID,
			SessionID: sessionID,
		})
		if err != nil {
			t.Fatalf("CreateAccessToken() error = %v", err)
		}

		principal, err := verifier.VerifyAccessToken(tokenString)
		if err != nil {
			t.Fatalf("VerifyAccessToken() error = %v", err)
		}
		if principal.UserID != userID {
			t.Errorf("UserID = %v, want %v", principal.UserID, userID)
		}
		if principal.SessionID != sessionID {
			t.Errorf("SessionID = %v, want %v", principal.SessionID, sessionID)
		}
		if principal.TokenID == uuid.Nil {
			t.Errorf("expected auto-generated non-nil TokenID, got %v", principal.TokenID)
		}
		if principal.TenantID != nil {
			t.Errorf("expected nil TenantID, got %v", principal.TenantID)
		}
	})

	t.Run("missing user id fails", func(t *testing.T) {
		_, err := mgr.CreateAccessToken(auth.Claims{
			UserID:    uuid.Nil,
			SessionID: uuid.New(),
		})
		if err == nil {
			t.Fatal("expected error for missing UserID")
		}
	})

	t.Run("missing session id fails", func(t *testing.T) {
		_, err := mgr.CreateAccessToken(auth.Claims{
			UserID:    uuid.New(),
			SessionID: uuid.Nil,
		})
		if err == nil {
			t.Fatal("expected error for missing SessionID")
		}
	})
}

func TestJWTManager_SharedVerifier_Rejections(t *testing.T) {
	pub, priv := generateEd25519(t)
	_, otherPriv := generateEd25519(t)

	keyID := "key-1"
	issuer := "orb-iam"
	audience := "orb-platform"

	mgr, err := auth.NewJWTManager(priv, keyID, issuer, audience, 15*time.Minute)
	if err != nil {
		t.Fatalf("init JWTManager: %v", err)
	}

	verifier, err := jwtverify.NewVerifier(
		map[string]ed25519.PublicKey{keyID: pub},
		issuer,
		audience,
	)
	if err != nil {
		t.Fatalf("init Verifier: %v", err)
	}

	t.Run("valid token accepted as baseline", func(t *testing.T) {
		tokenString, err := mgr.CreateAccessToken(auth.Claims{
			UserID:    uuid.New(),
			SessionID: uuid.New(),
		})
		if err != nil {
			t.Fatalf("create token: %v", err)
		}
		if _, err := verifier.VerifyAccessToken(tokenString); err != nil {
			t.Fatalf("expected valid token verification: %v", err)
		}
	})

	t.Run("invalid signature rejected", func(t *testing.T) {
		otherMgr, err := auth.NewJWTManager(otherPriv, keyID, issuer, audience, 15*time.Minute)
		if err != nil {
			t.Fatalf("init other JWTManager: %v", err)
		}

		tokenString, err := otherMgr.CreateAccessToken(auth.Claims{
			UserID:    uuid.New(),
			SessionID: uuid.New(),
		})
		if err != nil {
			t.Fatalf("create token with other key: %v", err)
		}

		if _, err := verifier.VerifyAccessToken(tokenString); err == nil {
			t.Fatal("expected signature verification failure")
		}
	})

	t.Run("unknown kid rejected", func(t *testing.T) {
		unknownKeyMgr, err := auth.NewJWTManager(priv, "unknown-key", issuer, audience, 15*time.Minute)
		if err != nil {
			t.Fatalf("init unknown key JWTManager: %v", err)
		}

		tokenString, err := unknownKeyMgr.CreateAccessToken(auth.Claims{
			UserID:    uuid.New(),
			SessionID: uuid.New(),
		})
		if err != nil {
			t.Fatalf("create token with unknown kid: %v", err)
		}

		if _, err := verifier.VerifyAccessToken(tokenString); err == nil {
			t.Fatal("expected unknown kid failure")
		}
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		wrongIssuerMgr, err := auth.NewJWTManager(priv, keyID, "wrong-issuer", audience, 15*time.Minute)
		if err != nil {
			t.Fatalf("init wrong issuer JWTManager: %v", err)
		}

		tokenString, err := wrongIssuerMgr.CreateAccessToken(auth.Claims{
			UserID:    uuid.New(),
			SessionID: uuid.New(),
		})
		if err != nil {
			t.Fatalf("create token with wrong issuer: %v", err)
		}

		if _, err := verifier.VerifyAccessToken(tokenString); err == nil {
			t.Fatal("expected wrong issuer failure")
		}
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		wrongAudMgr, err := auth.NewJWTManager(priv, keyID, issuer, "wrong-aud", 15*time.Minute)
		if err != nil {
			t.Fatalf("init wrong aud JWTManager: %v", err)
		}

		tokenString, err := wrongAudMgr.CreateAccessToken(auth.Claims{
			UserID:    uuid.New(),
			SessionID: uuid.New(),
		})
		if err != nil {
			t.Fatalf("create token with wrong aud: %v", err)
		}

		if _, err := verifier.VerifyAccessToken(tokenString); err == nil {
			t.Fatal("expected wrong audience failure")
		}
	})
}
