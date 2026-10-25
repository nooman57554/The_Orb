package jwtverify

import (
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

// Verifier validates EdDSA access tokens and returns verified identity.Principal objects.
type Verifier struct {
	publicKeys map[string]ed25519.PublicKey
	issuer     string
	audience   string
}

var _ identity.TokenVerifier = (*Verifier)(nil)

type tokenClaims struct {
	SessionID string `json:"sid"`
	TenantID  string `json:"tid,omitempty"`
	jwt.RegisteredClaims
}

// NewVerifier creates a new Verifier using trusted Ed25519 public keys and expected issuer/audience.
func NewVerifier(
	publicKeys map[string]ed25519.PublicKey,
	issuer string,
	audience string,
) (*Verifier, error) {
	if strings.TrimSpace(issuer) == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, fmt.Errorf("audience is required")
	}
	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("at least one public key is required")
	}

	keys := make(map[string]ed25519.PublicKey, len(publicKeys))
	for kid, key := range publicKeys {
		if strings.TrimSpace(kid) == "" {
			return nil, fmt.Errorf("key ID cannot be empty")
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key size for key ID %q", kid)
		}
		keys[kid] = append(ed25519.PublicKey(nil), key...)
	}

	return &Verifier{
		publicKeys: keys,
		issuer:     issuer,
		audience:   audience,
	}, nil
}

// VerifyAccessToken verifies the given access token string, validates signatures, timestamps,
// and identity claims, and returns an authenticated identity.Principal.
func (v *Verifier) VerifyAccessToken(tokenString string) (*identity.Principal, error) {
	var jc tokenClaims

	token, err := jwt.ParseWithClaims(
		tokenString,
		&jc,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodEdDSA {
				return nil, fmt.Errorf("unexpected signing algorithm %q, expected EdDSA", token.Method.Alg())
			}

			kid, ok := token.Header["kid"].(string)
			if !ok || strings.TrimSpace(kid) == "" {
				return nil, fmt.Errorf("missing or invalid key ID in token header")
			}

			key, exists := v.publicKeys[kid]
			if !exists {
				return nil, fmt.Errorf("unknown key ID %q", kid)
			}

			return key, nil
		},
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("verify access token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}

	if jc.ExpiresAt == nil || jc.IssuedAt == nil {
		return nil, fmt.Errorf("required token timestamps are missing")
	}

	userID, err := uuid.Parse(jc.Subject)
	if err != nil || userID == uuid.Nil {
		return nil, fmt.Errorf("invalid token subject UUID")
	}

	sessionID, err := uuid.Parse(jc.SessionID)
	if err != nil || sessionID == uuid.Nil {
		return nil, fmt.Errorf("invalid token session ID UUID")
	}

	tokenID, err := uuid.Parse(jc.ID)
	if err != nil || tokenID == uuid.Nil {
		return nil, fmt.Errorf("invalid token ID UUID")
	}

	var tenantID *uuid.UUID
	if strings.TrimSpace(jc.TenantID) != "" {
		parsedTenantID, err := uuid.Parse(jc.TenantID)
		if err != nil || parsedTenantID == uuid.Nil {
			return nil, fmt.Errorf("invalid token tenant ID UUID")
		}
		tenantID = &parsedTenantID
	}

	principal := &identity.Principal{
		UserID:    userID,
		SessionID: sessionID,
		TokenID:   tokenID,
		TenantID:  tenantID,
	}

	if err := principal.Validate(); err != nil {
		return nil, fmt.Errorf("invalid principal claims: %w", err)
	}

	return principal, nil
}
