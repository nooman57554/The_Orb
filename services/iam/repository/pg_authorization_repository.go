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

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM role_assignments ra
			JOIN roles r ON r.id = ra.role_id AND r.scope = 'platform'
			JOIN role_permissions rp ON rp.role_id = r.id
			JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'platform'
			JOIN users u ON u.id = ra.user_id
			WHERE ra.user_id = $1
			  AND ra.tenant_id IS NULL
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

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM role_assignments ra
			JOIN roles r ON r.id = ra.role_id AND r.scope IN ('system_tenant', 'custom_tenant')
			JOIN role_permissions rp ON rp.role_id = r.id
			JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'tenant'
			JOIN users u ON u.id = ra.user_id
			JOIN tenants t ON t.id = ra.tenant_id
			WHERE ra.user_id = $1
			  AND ra.tenant_id = $2
			  AND p.name = $3
			  AND u.status = 'active'
			  AND t.status = 'active'
			  AND (r.scope != 'custom_tenant' OR r.tenant_id = ra.tenant_id)
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

	const query = `
		SELECT EXISTS (
			SELECT 1
			FROM role_assignments ra
			JOIN users u ON u.id = ra.user_id
			JOIN tenants t ON t.id = ra.tenant_id
			WHERE ra.user_id = $1
			  AND ra.tenant_id = $2
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

	const query = `
		SELECT r.id, r.name, r.scope, r.tenant_id, r.description, r.created_at, r.updated_at
		FROM role_assignments ra
		JOIN roles r ON r.id = ra.role_id
		JOIN users u ON u.id = ra.user_id
		JOIN tenants t ON t.id = ra.tenant_id
		WHERE ra.user_id = $1
		  AND ra.tenant_id = $2
		  AND u.status = 'active'
		  AND t.status = 'active'
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

	const query = `
		SELECT COUNT(DISTINCT ra.user_id)
		FROM role_assignments ra
		JOIN users u ON u.id = ra.user_id
		JOIN tenants t ON t.id = ra.tenant_id
		JOIN roles r ON r.id = ra.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'tenant'
		WHERE ra.tenant_id = $1
		  AND u.status = 'active'
		  AND t.status = 'active'
		  AND (r.name = 'TENANT_ADMIN_RW' OR p.name IN ('user.assign_role', 'role.assign'))
	`

	var count int
	err := r.db.Pool().QueryRow(ctx, query, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active tenant admins: %w", err)
	}

	return count, nil
}

func (r *PostgresAuthorizationRepository) IsUserActive(
	ctx context.Context,
	userID uuid.UUID,
) (bool, error) {
	if userID == uuid.Nil {
		return false, nil
	}

	const query = `
		SELECT EXISTS (
			SELECT 1 FROM users
			WHERE id = $1 AND status = 'active'
		)
	`

	var active bool
	err := r.db.Pool().QueryRow(ctx, query, userID).Scan(&active)
	if err != nil {
		return false, fmt.Errorf("check user active: %w", err)
	}

	return active, nil
}
