package auth

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTManager struct {
	privateKey  ed25519.PrivateKey
	activeKeyID string
	issuer      string
	audience    string
	ttl         time.Duration
}

type accessTokenClaims struct {
	SessionID string `json:"sid"`
	TenantID  string `json:"tid,omitempty"`
	jwt.RegisteredClaims
}

func NewJWTManager(
	privateKey ed25519.PrivateKey,
	activeKeyID string,
	issuer string,
	audience string,
	ttl time.Duration,
) (*JWTManager, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key")
	}
	if activeKeyID == "" || issuer == "" || audience == "" {
		return nil, fmt.Errorf("key ID, issuer, and audience are required")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("token TTL must be positive")
	}

	return &JWTManager{
		privateKey:  append(ed25519.PrivateKey(nil), privateKey...),
		activeKeyID: activeKeyID,
		issuer:      issuer,
		audience:    audience,
		ttl:         ttl,
	}, nil
}

func (m *JWTManager) CreateAccessToken(claims Claims) (string, error) {
	if claims.UserID == uuid.Nil || claims.SessionID == uuid.Nil {
		return "", fmt.Errorf("user ID and session ID are required")
	}

	tokenID := claims.TokenID
	if tokenID == uuid.Nil {
		var err error
		tokenID, err = uuid.NewV7()
		if err != nil {
			return "", fmt.Errorf("generate token ID: %w", err)
		}
	}

	now := time.Now()

	jc := accessTokenClaims{
		SessionID: claims.SessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   claims.UserID.String(),
			Audience:  jwt.ClaimStrings{m.audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        tokenID.String(),
		},
	}

	if claims.TenantID != nil {
		jc.TenantID = claims.TenantID.String()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jc)
	token.Header["kid"] = m.activeKeyID

	signed, err := token.SignedString(m.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}
