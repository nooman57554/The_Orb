package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
)

type PostgresAuthorizationRepository struct {
	db *dbconnector.DBConnector
}

var _ AuthorizationRepository = (*PostgresAuthorizationRepository)(nil)

func NewPostgresAuthorizationRepository(db *dbconnector.DBConnector) *PostgresAuthorizationRepository {
	return &PostgresAuthorizationRepository{db: db}
}

func (r *PostgresAuthorizationRepository) HasPlatformPermission(
	ctx context.Context,
	userID uuid.UUID,
	permission string,
) (bool, error) {
	if userID == uuid.Nil || permission == "" {
		return false, nil
	}
	if r.db == nil || r.db.Pool() == nil {
		return false, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM platform_role_assignments pra
			JOIN roles r ON r.id = pra.role_id AND r.scope = 'platform'
			JOIN role_permissions rp ON rp.role_id = r.id
			JOIN permissions p ON p.id = rp.permission_id
			JOIN users u ON u.id = pra.user_id
			WHERE pra.user_id = $1
			  AND p.name = $2
			  AND u.status = 'active'
		)
	`

	var exists bool
	err := r.db.Pool().QueryRow(ctx, query, userID, permission).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check platform permission: %w", err)
	}

	return exists, nil
}

func (r *PostgresAuthorizationRepository) HasTenantPermission(
	ctx context.Context,
	userID uuid.UUID,
	tenantID uuid.UUID,
	permission string,
) (bool, error) {
	if userID == uuid.Nil || tenantID == uuid.Nil || permission == "" {
		return false, nil
	}
	if r.db == nil || r.db.Pool() == nil {
		return false, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM tenant_role_assignments tra
			JOIN roles r ON r.id = tra.role_id AND r.scope IN ('system_tenant', 'custom_tenant')
			JOIN role_permissions rp ON rp.role_id = r.id
			JOIN permissions p ON p.id = rp.permission_id
			JOIN users u ON u.id = tra.user_id
			JOIN tenants t ON t.id = tra.tenant_id
			WHERE tra.user_id = $1
			  AND tra.tenant_id = $2
			  AND p.name = $3
			  AND u.status = 'active'
			  AND t.status = 'active'
			  AND (r.scope != 'custom_tenant' OR r.tenant_id = tra.tenant_id)
		)
	`

	var exists bool
	err := r.db.Pool().QueryRow(ctx, query, userID, tenantID, permission).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check tenant permission: %w", err)
	}

	return exists, nil
}
