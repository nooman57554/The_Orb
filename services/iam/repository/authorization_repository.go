package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

// AuthorizationRepository defines the interface for database-backed authorization checks.
type AuthorizationRepository interface {
	// HasPlatformPermission checks if a user has been granted a specific platform-scoped permission
	// via role_assignments (tenant_id IS NULL), verifying that the user status is active.
	HasPlatformPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)

	// HasTenantPermission checks if a user has been granted a specific tenant-scoped permission
	// within a specific tenant via role_assignments, verifying that both the user and
	// the tenant statuses are active.
	HasTenantPermission(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, permission string) (bool, error)

	// UserBelongsToTenant checks if an active user has an assignment in an active tenant.
	UserBelongsToTenant(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) (bool, error)

	// GetTenantRole returns the role assigned to a user in a tenant.
	GetTenantRole(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID) (*model.Role, error)

	// CountActiveTenantAdmins counts the number of active users with administrative privileges in a tenant.
	CountActiveTenantAdmins(ctx context.Context, tenantID uuid.UUID) (int, error)

	// IsUserActive checks whether a user exists and is active.
	IsUserActive(ctx context.Context, userID uuid.UUID) (bool, error)
}
