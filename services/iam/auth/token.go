package auth

import (
	"github.com/google/uuid"
)

// Claims represents the identity claims provided as input to CreateAccessToken.
type Claims struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	TokenID   uuid.UUID
	TenantID  *uuid.UUID
}
