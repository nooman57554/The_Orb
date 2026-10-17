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
	publicKeys  map[string]ed25519.PublicKey
	issuer      string
	audience    string
	ttl         time.Duration
}

type jwtClaims struct {
	SessionID string `json:"sid"`
	TenantID  string `json:"tid,omitempty"`
	jwt.RegisteredClaims
}

func NewJWTManager(
	privateKey ed25519.PrivateKey,
	activeKeyID string,
	publicKeys map[string]ed25519.PublicKey,
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
	if len(publicKeys[activeKeyID]) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("active public key is missing or invalid")
	}

	// Copy the map so callers cannot change our trusted key set
	// by mutating their original map.
	keys := make(map[string]ed25519.PublicKey, len(publicKeys))
	for id, key := range publicKeys {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key entry")
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}

	return &JWTManager{
		privateKey:  append(ed25519.PrivateKey(nil), privateKey...),
		activeKeyID: activeKeyID,
		publicKeys:  keys,
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

	jc := jwtClaims{
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

func (m *JWTManager) VerifyAccessToken(tokenString string) (*Claims, error) {
	var jc jwtClaims

	token, err := jwt.ParseWithClaims(
		tokenString,
		&jc,
		func(token *jwt.Token) (any, error) {
			// Never accept a different signing algorithm.
			if token.Method != jwt.SigningMethodEdDSA {
				return nil, fmt.Errorf("unexpected signing algorithm")
			}

			kid, ok := token.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, fmt.Errorf("missing key ID")
			}

			key, ok := m.publicKeys[kid]
			if !ok {
				return nil, fmt.Errorf("unknown key ID")
			}
			return key, nil
		},
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("verify access token: %w", err)
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}

	userID, err := uuid.Parse(jc.Subject)
	if err != nil {
		return nil, fmt.Errorf("invalid token subject")
	}
	sessionID, err := uuid.Parse(jc.SessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid token session ID")
	}
	tokenID, err := uuid.Parse(jc.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid token ID")
	}

	var tenantID *uuid.UUID
	if jc.TenantID != "" {
		id, err := uuid.Parse(jc.TenantID)
		if err != nil {
			return nil, fmt.Errorf("invalid token tenant ID")
		}
		tenantID = &id
	}

	if jc.ExpiresAt == nil || jc.IssuedAt == nil {
		return nil, fmt.Errorf("required token timestamps are missing")
	}

	return &Claims{
		UserID:    userID,
		SessionID: sessionID,
		TenantID:  tenantID,
		Issuer:    jc.Issuer,
		Audience:  m.audience,
		ExpiresAt: jc.ExpiresAt.Time,
		IssuedAt:  jc.IssuedAt.Time,
		TokenID:   tokenID,
	}, nil
}
