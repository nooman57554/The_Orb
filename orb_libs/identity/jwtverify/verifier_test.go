package jwtverify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity/jwtverify"
)

type jwtClaims struct {
	SessionID string `json:"sid"`
	TenantID  string `json:"tid,omitempty"`
	jwt.RegisteredClaims
}

type testFixture struct {
	privKey  ed25519.PrivateKey
	pubKey   ed25519.PublicKey
	keyID    string
	issuer   string
	audience string
	verifier *jwtverify.Verifier
}

func setupFixture(t *testing.T) *testFixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	keyID := "test-key-1"
	issuer := "orb-iam"
	audience := "orb-platform"

	verifier, err := jwtverify.NewVerifier(
		map[string]ed25519.PublicKey{keyID: pub},
		issuer,
		audience,
	)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}

	return &testFixture{
		privKey:  priv,
		pubKey:   pub,
		keyID:    keyID,
		issuer:   issuer,
		audience: audience,
		verifier: verifier,
	}
}

func (f *testFixture) signToken(t *testing.T, claims jwtClaims, kid string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(f.privKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func TestNewVerifier_Validation(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)

	// Missing issuer
	if _, err := jwtverify.NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, "", "aud"); err == nil {
		t.Error("expected error for empty issuer")
	}

	// Missing audience
	if _, err := jwtverify.NewVerifier(map[string]ed25519.PublicKey{"k1": pub}, "iss", ""); err == nil {
		t.Error("expected error for empty audience")
	}

	// Empty keys
	if _, err := jwtverify.NewVerifier(map[string]ed25519.PublicKey{}, "iss", "aud"); err == nil {
		t.Error("expected error for empty public keys map")
	}

	// Invalid key size
	if _, err := jwtverify.NewVerifier(map[string]ed25519.PublicKey{"k1": []byte("too-short")}, "iss", "aud"); err == nil {
		t.Error("expected error for invalid key size")
	}

	// Empty key ID
	if _, err := jwtverify.NewVerifier(map[string]ed25519.PublicKey{"": pub}, "iss", "aud"); err == nil {
		t.Error("expected error for empty key ID")
	}
}

func TestVerifier_VerifyAccessToken_Valid(t *testing.T) {
	f := setupFixture(t)

	userID := uuid.New()
	sessionID := uuid.New()
	tokenID := uuid.New()
	tenantID := uuid.New()
	now := time.Now()

	claims := jwtClaims{
		SessionID: sessionID.String(),
		TenantID:  tenantID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        tokenID.String(),
		},
	}

	tokenString := f.signToken(t, claims, f.keyID)

	principal, err := f.verifier.VerifyAccessToken(tokenString)
	if err != nil {
		t.Fatalf("VerifyAccessToken failed: %v", err)
	}

	if principal.UserID != userID {
		t.Errorf("UserID = %s, want %s", principal.UserID, userID)
	}
	if principal.SessionID != sessionID {
		t.Errorf("SessionID = %s, want %s", principal.SessionID, sessionID)
	}
	if principal.TokenID != tokenID {
		t.Errorf("TokenID = %s, want %s", principal.TokenID, tokenID)
	}
	if principal.TenantID == nil || *principal.TenantID != tenantID {
		t.Errorf("TenantID = %v, want %s", principal.TenantID, tenantID)
	}
}

func TestVerifier_VerifyAccessToken_ValidWithoutTenant(t *testing.T) {
	f := setupFixture(t)

	userID := uuid.New()
	sessionID := uuid.New()
	tokenID := uuid.New()
	now := time.Now()

	claims := jwtClaims{
		SessionID: sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        tokenID.String(),
		},
	}

	tokenString := f.signToken(t, claims, f.keyID)

	principal, err := f.verifier.VerifyAccessToken(tokenString)
	if err != nil {
		t.Fatalf("VerifyAccessToken failed: %v", err)
	}

	if principal.TenantID != nil {
		t.Errorf("expected nil TenantID, got %v", principal.TenantID)
	}
}

func TestVerifier_VerifyAccessToken_InvalidSignature(t *testing.T) {
	f := setupFixture(t)

	// Sign with a different private key
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	claims := jwtClaims{
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = f.keyID
	signed, _ := token.SignedString(otherPriv)

	if _, err := f.verifier.VerifyAccessToken(signed); err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestVerifier_VerifyAccessToken_MissingOrUnknownKid(t *testing.T) {
	f := setupFixture(t)

	claims := jwtClaims{
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}

	// 1. Missing kid
	missingKid := f.signToken(t, claims, "")
	if _, err := f.verifier.VerifyAccessToken(missingKid); err == nil {
		t.Error("expected error for missing kid")
	}

	// 2. Unknown kid
	unknownKid := f.signToken(t, claims, "unknown-key")
	if _, err := f.verifier.VerifyAccessToken(unknownKid); err == nil {
		t.Error("expected error for unknown kid")
	}
}

func TestVerifier_VerifyAccessToken_WrongAlgorithm(t *testing.T) {
	f := setupFixture(t)

	claims := jwtClaims{
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}

	// Sign with HMAC instead of EdDSA
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = f.keyID
	signed, _ := token.SignedString([]byte("some-secret"))

	if _, err := f.verifier.VerifyAccessToken(signed); err == nil {
		t.Error("expected error for wrong signing algorithm")
	}
}

func TestVerifier_VerifyAccessToken_WrongIssuerOrAudience(t *testing.T) {
	f := setupFixture(t)

	// Wrong issuer
	claims1 := jwtClaims{
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "wrong-issuer",
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}
	if _, err := f.verifier.VerifyAccessToken(f.signToken(t, claims1, f.keyID)); err == nil {
		t.Error("expected error for wrong issuer")
	}

	// Wrong audience
	claims2 := jwtClaims{
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{"wrong-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}
	if _, err := f.verifier.VerifyAccessToken(f.signToken(t, claims2, f.keyID)); err == nil {
		t.Error("expected error for wrong audience")
	}
}

func TestVerifier_VerifyAccessToken_ExpiredToken(t *testing.T) {
	f := setupFixture(t)
	now := time.Now()

	claims := jwtClaims{
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(-5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now.Add(-20 * time.Minute)),
			ID:        uuid.New().String(),
		},
	}

	tokenString := f.signToken(t, claims, f.keyID)
	if _, err := f.verifier.VerifyAccessToken(tokenString); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestVerifier_VerifyAccessToken_InvalidUUIDClaims(t *testing.T) {
	f := setupFixture(t)
	now := time.Now()

	validID := uuid.New().String()

	tests := []struct {
		name      string
		subject   string
		sessionID string
		tokenID   string
		tenantID  string
	}{
		{name: "invalid subject", subject: "not-a-uuid", sessionID: validID, tokenID: validID},
		{name: "nil subject", subject: uuid.Nil.String(), sessionID: validID, tokenID: validID},
		{name: "invalid session", subject: validID, sessionID: "not-a-uuid", tokenID: validID},
		{name: "nil session", subject: validID, sessionID: uuid.Nil.String(), tokenID: validID},
		{name: "invalid token id", subject: validID, sessionID: validID, tokenID: "not-a-uuid"},
		{name: "nil token id", subject: validID, sessionID: validID, tokenID: uuid.Nil.String()},
		{name: "invalid tenant", subject: validID, sessionID: validID, tokenID: validID, tenantID: "not-a-uuid"},
		{name: "nil tenant", subject: validID, sessionID: validID, tokenID: validID, tenantID: uuid.Nil.String()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := jwtClaims{
				SessionID: tc.sessionID,
				TenantID:  tc.tenantID,
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:    f.issuer,
					Subject:   tc.subject,
					Audience:  jwt.ClaimStrings{f.audience},
					ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(now),
					ID:        tc.tokenID,
				},
			}
			tokenString := f.signToken(t, claims, f.keyID)
			if _, err := f.verifier.VerifyAccessToken(tokenString); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestVerifier_VerifyAccessToken_FutureNbf(t *testing.T) {
	f := setupFixture(t)
	now := time.Now()

	claims := jwtClaims{
		SessionID: uuid.New().String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   uuid.New().String(),
			Audience:  jwt.ClaimStrings{f.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(10 * time.Minute)), // Future nbf
			ID:        uuid.New().String(),
		},
	}

	tokenString := f.signToken(t, claims, f.keyID)
	if _, err := f.verifier.VerifyAccessToken(tokenString); err == nil {
		t.Error("expected error for token not yet valid (nbf in future)")
	}
}
