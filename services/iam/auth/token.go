package auth

import (
	"time"

	"github.com/google/uuid"
)

type Claims struct {
	TokenID   uuid.UUID
	UserID    uuid.UUID
	SessionID uuid.UUID
	TenantID  *uuid.UUID
	Issuer    string
	Audience  string
	ExpiresAt time.Time
	IssuedAt  time.Time
}
