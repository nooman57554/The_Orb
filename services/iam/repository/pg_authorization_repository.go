package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
	"github.com/nooman57554/The_Orb/services/iam/model"
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

func (r *PostgresAuthorizationRepository) UserBelongsToTenant(
	ctx context.Context,
	userID uuid.UUID,
	tenantID uuid.UUID,
) (bool, error) {
	if userID == uuid.Nil || tenantID == uuid.Nil {
		return false, nil
	}
	if r.db == nil || r.db.Pool() == nil {
		return false, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM tenant_role_assignments tra
			JOIN users u ON u.id = tra.user_id
			JOIN tenants t ON t.id = tra.tenant_id
			WHERE tra.user_id = $1
			  AND tra.tenant_id = $2
			  AND u.status = 'active'
			  AND t.status = 'active'
		)
	`

	var exists bool
	err := r.db.Pool().QueryRow(ctx, query, userID, tenantID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check user belongs to tenant: %w", err)
	}

	return exists, nil
}

func (r *PostgresAuthorizationRepository) GetTenantRole(
	ctx context.Context,
	userID uuid.UUID,
	tenantID uuid.UUID,
) (*model.Role, error) {
	if userID == uuid.Nil || tenantID == uuid.Nil {
		return nil, fmt.Errorf("tenant role: %w", ErrNotFound)
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT r.id, r.name, r.scope, r.tenant_id, r.description, r.created_at, r.updated_at
		FROM tenant_role_assignments tra
		JOIN roles r ON r.id = tra.role_id
		WHERE tra.user_id = $1
		  AND tra.tenant_id = $2
	`

	var role model.Role
	err := r.db.Pool().QueryRow(ctx, query, userID, tenantID).Scan(
		&role.ID,
		&role.Name,
		&role.Scope,
		&role.TenantID,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("tenant role: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get tenant role: %w", err)
	}

	return &role, nil
}

func (r *PostgresAuthorizationRepository) CountActiveTenantAdmins(
	ctx context.Context,
	tenantID uuid.UUID,
) (int, error) {
	if tenantID == uuid.Nil {
		return 0, nil
	}
	if r.db == nil || r.db.Pool() == nil {
		return 0, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT COUNT(DISTINCT tra.user_id)
		FROM tenant_role_assignments tra
		JOIN users u ON u.id = tra.user_id
		JOIN tenants t ON t.id = tra.tenant_id
		JOIN roles r ON r.id = tra.role_id
		JOIN role_permissions rp ON rp.role_id = r.id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE tra.tenant_id = $1
		  AND u.status = 'active'
		  AND t.status = 'active'
		  AND p.name IN ('user.assign_role', 'role.assign')
	`

	var count int
	err := r.db.Pool().QueryRow(ctx, query, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active tenant admins: %w", err)
	}

	return count, nil
}
