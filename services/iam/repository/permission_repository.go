package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

type PermissionRepository interface {
	ListAll(ctx context.Context) ([]model.Permission, error)
	GetByIDs(ctx context.Context, ids []uuid.UUID) ([]model.Permission, error)
	GetByName(ctx context.Context, name string) (*model.Permission, error)
}
