package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

var (
	ErrLastPlatformAdmin = errors.New("cannot remove or demote the last active platform administrator")
	ErrLastTenantAdmin   = errors.New("cannot remove or demote the last active tenant administrator")
)

type RoleAssignmentRepository interface {
	AssignTenantRole(ctx context.Context, userID, tenantID, roleID uuid.UUID) error
	RemoveTenantRole(ctx context.Context, userID, tenantID uuid.UUID) error
	ListUsersByTenantRole(ctx context.Context, tenantID, roleID uuid.UUID) ([]model.TenantMemberRecord, error)

	AssignPlatformRole(ctx context.Context, userID, roleID uuid.UUID) error
	RemovePlatformRole(ctx context.Context, userID uuid.UUID) error
	GetPlatformRole(ctx context.Context, userID uuid.UUID) (*model.Role, error)
	CountPlatformAdmins(ctx context.Context) (int, error)
}
