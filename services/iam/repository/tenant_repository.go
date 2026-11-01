package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

var (
	ErrDuplicateSlug = errors.New("duplicate slug: tenant already exists")
)

type TenantRepository interface {
	Create(ctx context.Context, tenant *model.Tenant) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error)
	GetBySlug(ctx context.Context, slug string) (*model.Tenant, error)
	List(ctx context.Context, offset, limit int) ([]model.Tenant, int, error)
	Update(ctx context.Context, tenant *model.Tenant) error
	SetStatus(ctx context.Context, id uuid.UUID, status string) error
}
