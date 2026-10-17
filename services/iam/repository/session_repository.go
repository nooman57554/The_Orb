package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

type SessionRepository interface {
	Create(ctx context.Context, session *model.Session, tokenHash string) error
	GetByRefreshTokenHash(
		ctx context.Context,
		tokenHash string,
	) (*model.Session, error)
	RotateRefreshToken(
		ctx context.Context,
		oldTokenHash string,
		newTokenHash string,
	) (*model.Session, error)
	RevokeByRefreshTokenHash(ctx context.Context, tokenHash string) error
	IsActive(ctx context.Context, sessionID uuid.UUID) (bool, error)
}
