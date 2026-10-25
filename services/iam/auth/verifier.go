package auth

import (
	"fmt"

	"github.com/nooman57554/The_Orb/orb_libs/identity"
)

// JWTPrincipalVerifier adapts JWTManager to satisfy identity.TokenVerifier.
type JWTPrincipalVerifier struct {
	jwtManager *JWTManager
}

var _ identity.TokenVerifier = (*JWTPrincipalVerifier)(nil)

// NewJWTPrincipalVerifier constructs a new JWTPrincipalVerifier adapting the provided JWTManager.
func NewJWTPrincipalVerifier(jwtManager *JWTManager) (*JWTPrincipalVerifier, error) {
	if jwtManager == nil {
		return nil, fmt.Errorf("jwt manager is required")
	}

	return &JWTPrincipalVerifier{
		jwtManager: jwtManager,
	}, nil
}

// VerifyAccessToken verifies an access token string using the underlying JWTManager
// and maps the verified IAM Claims into a shared identity.Principal.
func (v *JWTPrincipalVerifier) VerifyAccessToken(tokenString string) (*identity.Principal, error) {
	claims, err := v.jwtManager.VerifyAccessToken(tokenString)
	if err != nil {
		return nil, err
	}

	return ClaimsToPrincipal(claims)
}

// ClaimsToPrincipal converts an IAM auth.Claims struct into a shared identity.Principal.
func ClaimsToPrincipal(claims *Claims) (*identity.Principal, error) {
	if claims == nil {
		return nil, fmt.Errorf("claims cannot be nil")
	}

	principal := &identity.Principal{
		UserID:    claims.UserID,
		SessionID: claims.SessionID,
		TokenID:   claims.TokenID,
		TenantID:  claims.TenantID,
	}

	if err := principal.Validate(); err != nil {
		return nil, fmt.Errorf("invalid principal from claims: %w", err)
	}

	return principal, nil
}
