package repository

import (
	"context"

	"github.com/google/uuid"
)

// AuthorizationRepository defines the interface for database-backed authorization checks.
type AuthorizationRepository interface {
	// HasPlatformPermission checks if a user has been granted a specific platform-scoped permission
	// via platform_role_assignments, verifying that the user status is active.
	HasPlatformPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)

	// HasTenantPermission checks if a user has been granted a specific tenant-scoped permission
	// within a specific tenant via tenant_role_assignments, verifying that both the user and
	// the tenant statuses are active.
	HasTenantPermission(ctx context.Context, userID uuid.UUID, tenantID uuid.UUID, permission string) (bool, error)
}
