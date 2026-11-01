package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

var (
	ErrDuplicateRoleName   = errors.New("duplicate role name: role already exists in this scope")
	ErrRoleHasAssignments  = errors.New("cannot delete role with active assignments")
	ErrSystemRoleImmutable = errors.New("system roles cannot be modified or deleted")
)

type RoleRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*model.Role, error)
	GetByNameAndScope(ctx context.Context, name, scope string, tenantID *uuid.UUID) (*model.Role, error)
	ListByTenant(ctx context.Context, tenantID uuid.UUID) ([]model.Role, error)
	ListPlatform(ctx context.Context) ([]model.Role, error)
	CreateCustom(ctx context.Context, role *model.Role, permissionIDs []uuid.UUID) error
	UpdateCustom(ctx context.Context, role *model.Role, permissionIDs []uuid.UUID) error
	DeleteCustom(ctx context.Context, id, tenantID uuid.UUID) error
	HasActiveAssignments(ctx context.Context, roleID uuid.UUID) (bool, error)
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]model.Permission, error)
}
