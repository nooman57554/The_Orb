package identity

import (
	"fmt"

	"github.com/google/uuid"
)

// Principal represents a transport-independent verified caller identity.
type Principal struct {
	UserID    uuid.UUID  `json:"user_id"`
	SessionID uuid.UUID  `json:"session_id"`
	TokenID   uuid.UUID  `json:"token_id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
}

// IsValid checks whether the principal is non-nil and has non-zero required identifiers.
func (p *Principal) IsValid() bool {
	if p == nil {
		return false
	}
	if p.UserID == uuid.Nil || p.SessionID == uuid.Nil || p.TokenID == uuid.Nil {
		return false
	}
	if p.TenantID != nil && *p.TenantID == uuid.Nil {
		return false
	}
	return true
}

// Validate returns an error describing why a principal is invalid, or nil if valid.
func (p *Principal) Validate() error {
	if p == nil {
		return fmt.Errorf("principal cannot be nil")
	}
	if p.UserID == uuid.Nil {
		return fmt.Errorf("user ID cannot be nil")
	}
	if p.SessionID == uuid.Nil {
		return fmt.Errorf("session ID cannot be nil")
	}
	if p.TokenID == uuid.Nil {
		return fmt.Errorf("token ID cannot be nil")
	}
	if p.TenantID != nil && *p.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID cannot be nil when specified")
	}
	return nil
}

// TokenVerifier defines the transport-independent contract for verifying an access token
// and returning the verified Principal.
type TokenVerifier interface {
	VerifyAccessToken(token string) (*Principal, error)
}
