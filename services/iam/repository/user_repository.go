package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

type UserRepository interface {
	Create(ctx context.Context, user *model.User) error
	CreateWithTenantRole(ctx context.Context, user *model.User, tenantID, roleID uuid.UUID) error
	GetByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	GetByIDInTenant(ctx context.Context, userID, tenantID uuid.UUID) (*model.TenantMemberRecord, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID, offset, limit int) ([]model.TenantMemberRecord, int, error)
	Update(ctx context.Context, user *model.User) error
	SetStatus(ctx context.Context, id uuid.UUID, status string) error
}
