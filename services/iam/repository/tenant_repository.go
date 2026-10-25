package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

type TenantRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error)
	Update(ctx context.Context, tenant *model.Tenant) error
}
