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

type PostgresRoleAssignmentRepository struct {
	db *dbconnector.DBConnector
}

var _ RoleAssignmentRepository = (*PostgresRoleAssignmentRepository)(nil)

func NewPostgresRoleAssignmentRepository(db *dbconnector.DBConnector) *PostgresRoleAssignmentRepository {
	return &PostgresRoleAssignmentRepository{db: db}
}

func (r *PostgresRoleAssignmentRepository) AssignTenantRole(
	ctx context.Context,
	userID, tenantID, roleID uuid.UUID,
) error {
	if userID == uuid.Nil || tenantID == uuid.Nil || roleID == uuid.Nil {
		return fmt.Errorf("user ID, tenant ID, and role ID are required")
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Lock the tenant row FOR UPDATE to serialize role assignments in this tenant
	var lockedTenantID uuid.UUID
	err = tx.QueryRow(ctx, "SELECT id FROM tenants WHERE id = $1 FOR UPDATE", tenantID).Scan(&lockedTenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("tenant: %w", ErrNotFound)
		}
		return fmt.Errorf("lock tenant: %w", err)
	}

	// 1. Check if the new role has tenant admin capabilities
	const checkNewRoleQuery = `
		SELECT EXISTS (
			SELECT 1 FROM roles r
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'tenant'
			WHERE r.id = $1 AND (r.name = 'TENANT_ADMIN_RW' OR p.name IN ('user.assign_role', 'role.assign'))
		)
	`
	var newRoleIsAdmin bool
	if err := tx.QueryRow(ctx, checkNewRoleQuery, roleID).Scan(&newRoleIsAdmin); err != nil {
		return fmt.Errorf("check new role admin capabilities: %w", err)
	}

	// 2. Check if the current user assignment in this tenant is an active tenant admin
	const checkCurrentAdminQuery = `
		SELECT EXISTS (
			SELECT 1
			FROM role_assignments ra
			JOIN users u ON u.id = ra.user_id
			JOIN tenants t ON t.id = ra.tenant_id
			JOIN roles r ON r.id = ra.role_id
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'tenant'
			WHERE ra.user_id = $1 AND ra.tenant_id = $2
			  AND u.status = 'active' AND t.status = 'active'
			  AND (r.name = 'TENANT_ADMIN_RW' OR p.name IN ('user.assign_role', 'role.assign'))
		)
	`
	var currentIsAdmin bool
	if err := tx.QueryRow(ctx, checkCurrentAdminQuery, userID, tenantID).Scan(&currentIsAdmin); err != nil {
		return fmt.Errorf("check current role admin capabilities: %w", err)
	}

	// 3. If demoting an active admin to a non-admin role, check count
	if currentIsAdmin && !newRoleIsAdmin {
		const countQuery = `
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
		if err := tx.QueryRow(ctx, countQuery, tenantID).Scan(&count); err != nil {
			return fmt.Errorf("count active tenant admins: %w", err)
		}
		if count <= 1 {
			return ErrLastTenantAdmin
		}
	}

	// 4. Upsert assignment
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate assignment id: %w", err)
	}

	const upsertQuery = `
		INSERT INTO role_assignments (id, user_id, tenant_id, role_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, tenant_id) WHERE tenant_id IS NOT NULL
		DO UPDATE SET role_id = EXCLUDED.role_id, created_at = NOW()
	`
	if _, err := tx.Exec(ctx, upsertQuery, id, userID, tenantID, roleID); err != nil {
		return fmt.Errorf("assign tenant role: %w", err)
	}

	return tx.Commit(ctx)
}

func (r *PostgresRoleAssignmentRepository) RemoveTenantRole(
	ctx context.Context,
	userID, tenantID uuid.UUID,
) error {
	if userID == uuid.Nil || tenantID == uuid.Nil {
		return fmt.Errorf("user ID and tenant ID are required")
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Lock the tenant row FOR UPDATE to serialize role operations in this tenant
	var lockedTenantID uuid.UUID
	err = tx.QueryRow(ctx, "SELECT id FROM tenants WHERE id = $1 FOR UPDATE", tenantID).Scan(&lockedTenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("tenant: %w", ErrNotFound)
		}
		return fmt.Errorf("lock tenant: %w", err)
	}

	// 1. Check if the current user assignment in this tenant is an active tenant admin
	const checkCurrentAdminQuery = `
		SELECT EXISTS (
			SELECT 1
			FROM role_assignments ra
			JOIN users u ON u.id = ra.user_id
			JOIN tenants t ON t.id = ra.tenant_id
			JOIN roles r ON r.id = ra.role_id
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'tenant'
			WHERE ra.user_id = $1 AND ra.tenant_id = $2
			  AND u.status = 'active' AND t.status = 'active'
			  AND (r.name = 'TENANT_ADMIN_RW' OR p.name IN ('user.assign_role', 'role.assign'))
		)
	`
	var currentIsAdmin bool
	if err := tx.QueryRow(ctx, checkCurrentAdminQuery, userID, tenantID).Scan(&currentIsAdmin); err != nil {
		return fmt.Errorf("check current role admin capabilities: %w", err)
	}

	if currentIsAdmin {
		const countQuery = `
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
		if err := tx.QueryRow(ctx, countQuery, tenantID).Scan(&count); err != nil {
			return fmt.Errorf("count active tenant admins: %w", err)
		}
		if count <= 1 {
			return ErrLastTenantAdmin
		}
	}

	const deleteQuery = `
		DELETE FROM role_assignments
		WHERE user_id = $1 AND tenant_id = $2
	`
	res, err := tx.Exec(ctx, deleteQuery, userID, tenantID)
	if err != nil {
		return fmt.Errorf("remove tenant role: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("membership: %w", ErrNotFound)
	}

	return tx.Commit(ctx)
}

func (r *PostgresRoleAssignmentRepository) ListUsersByTenantRole(
	ctx context.Context,
	tenantID, roleID uuid.UUID,
) ([]model.TenantMemberRecord, error) {
	if tenantID == uuid.Nil || roleID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID and role ID are required")
	}

	const query = `
		SELECT
			u.id,
			u.email,
			u.status,
			r.id,
			r.name,
			r.scope,
			ra.created_at
		FROM role_assignments ra
		JOIN users u ON u.id = ra.user_id
		JOIN roles r ON r.id = ra.role_id
		WHERE ra.tenant_id = $1 AND ra.role_id = $2
		ORDER BY ra.created_at DESC
	`

	rows, err := r.db.Pool().Query(ctx, query, tenantID, roleID)
	if err != nil {
		return nil, fmt.Errorf("list users by tenant role: %w", err)
	}
	defer rows.Close()

	records := make([]model.TenantMemberRecord, 0)
	for rows.Next() {
		var rec model.TenantMemberRecord
		if err := rows.Scan(
			&rec.UserID,
			&rec.Email,
			&rec.Status,
			&rec.RoleID,
			&rec.RoleName,
			&rec.RoleScope,
			&rec.JoinedAt,
		); err != nil {
			return nil, fmt.Errorf("scan tenant member: %w", err)
		}
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return records, nil
}

func (r *PostgresRoleAssignmentRepository) AssignPlatformRole(
	ctx context.Context,
	userID, roleID uuid.UUID,
) error {
	if userID == uuid.Nil || roleID == uuid.Nil {
		return fmt.Errorf("user ID and role ID are required")
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Acquire transaction-level advisory lock for platform admin operations
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('platform_admin_lock'))"); err != nil {
		return fmt.Errorf("acquire platform advisory lock: %w", err)
	}

	// 1. Check if the new role has platform admin capabilities
	const checkNewRoleQuery = `
		SELECT EXISTS (
			SELECT 1 FROM roles r
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'platform'
			WHERE r.id = $1 AND r.scope = 'platform' AND (r.name = 'PLATFORM_ADMIN' OR p.name = 'role.assign')
		)
	`
	var newRoleIsAdmin bool
	if err := tx.QueryRow(ctx, checkNewRoleQuery, roleID).Scan(&newRoleIsAdmin); err != nil {
		return fmt.Errorf("check new role admin capabilities: %w", err)
	}

	// 2. Check if the current user assignment is an active platform admin
	const checkCurrentAdminQuery = `
		SELECT EXISTS (
			SELECT 1
			FROM role_assignments ra
			JOIN users u ON u.id = ra.user_id
			JOIN roles r ON r.id = ra.role_id
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'platform'
			WHERE ra.user_id = $1 AND ra.tenant_id IS NULL AND u.status = 'active'
			  AND (r.name = 'PLATFORM_ADMIN' OR p.name = 'role.assign')
		)
	`
	var currentIsAdmin bool
	if err := tx.QueryRow(ctx, checkCurrentAdminQuery, userID).Scan(&currentIsAdmin); err != nil {
		return fmt.Errorf("check current role admin capabilities: %w", err)
	}

	// 3. If demoting an active admin to a non-admin role, check count
	if currentIsAdmin && !newRoleIsAdmin {
		const countQuery = `
			SELECT COUNT(DISTINCT ra.user_id)
			FROM role_assignments ra
			JOIN users u ON u.id = ra.user_id
			JOIN roles r ON r.id = ra.role_id
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'platform'
			WHERE ra.tenant_id IS NULL
			  AND u.status = 'active'
			  AND r.scope = 'platform'
			  AND (r.name = 'PLATFORM_ADMIN' OR p.name = 'role.assign')
		`
		var count int
		if err := tx.QueryRow(ctx, countQuery).Scan(&count); err != nil {
			return fmt.Errorf("count platform admins: %w", err)
		}
		if count <= 1 {
			return ErrLastPlatformAdmin
		}
	}

	// 4. Upsert assignment
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate assignment id: %w", err)
	}

	const upsertQuery = `
		INSERT INTO role_assignments (id, user_id, tenant_id, role_id)
		VALUES ($1, $2, NULL, $3)
		ON CONFLICT (user_id) WHERE tenant_id IS NULL
		DO UPDATE SET role_id = EXCLUDED.role_id, created_at = NOW()
	`
	if _, err := tx.Exec(ctx, upsertQuery, id, userID, roleID); err != nil {
		return fmt.Errorf("assign platform role: %w", err)
	}

	return tx.Commit(ctx)
}

func (r *PostgresRoleAssignmentRepository) RemovePlatformRole(
	ctx context.Context,
	userID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Acquire transaction-level advisory lock for platform admin operations
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('platform_admin_lock'))"); err != nil {
		return fmt.Errorf("acquire platform advisory lock: %w", err)
	}

	// 1. Check if user has an active platform role assignment
	const checkCurrentAdminQuery = `
		SELECT EXISTS (
			SELECT 1
			FROM role_assignments ra
			JOIN users u ON u.id = ra.user_id
			JOIN roles r ON r.id = ra.role_id
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'platform'
			WHERE ra.user_id = $1 AND ra.tenant_id IS NULL AND u.status = 'active'
			  AND (r.name = 'PLATFORM_ADMIN' OR p.name = 'role.assign')
		)
	`
	var currentIsAdmin bool
	if err := tx.QueryRow(ctx, checkCurrentAdminQuery, userID).Scan(&currentIsAdmin); err != nil {
		return fmt.Errorf("check current role admin capabilities: %w", err)
	}

	if currentIsAdmin {
		const countQuery = `
			SELECT COUNT(DISTINCT ra.user_id)
			FROM role_assignments ra
			JOIN users u ON u.id = ra.user_id
			JOIN roles r ON r.id = ra.role_id
			LEFT JOIN role_permissions rp ON rp.role_id = r.id
			LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'platform'
			WHERE ra.tenant_id IS NULL
			  AND u.status = 'active'
			  AND r.scope = 'platform'
			  AND (r.name = 'PLATFORM_ADMIN' OR p.name = 'role.assign')
		`
		var count int
		if err := tx.QueryRow(ctx, countQuery).Scan(&count); err != nil {
			return fmt.Errorf("count platform admins: %w", err)
		}
		if count <= 1 {
			return ErrLastPlatformAdmin
		}
	}

	const deleteQuery = `
		DELETE FROM role_assignments
		WHERE user_id = $1 AND tenant_id IS NULL
	`
	res, err := tx.Exec(ctx, deleteQuery, userID)
	if err != nil {
		return fmt.Errorf("remove platform role: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("platform role assignment: %w", ErrNotFound)
	}

	return tx.Commit(ctx)
}

func (r *PostgresRoleAssignmentRepository) GetPlatformRole(
	ctx context.Context,
	userID uuid.UUID,
) (*model.Role, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("user ID is required")
	}

	const query = `
		SELECT
			r.id,
			r.name,
			r.scope,
			r.tenant_id,
			r.description,
			r.created_at,
			r.updated_at
		FROM role_assignments ra
		JOIN roles r ON r.id = ra.role_id
		WHERE ra.user_id = $1 AND ra.tenant_id IS NULL
	`

	var role model.Role
	err := r.db.Pool().QueryRow(ctx, query, userID).Scan(
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
			return nil, fmt.Errorf("platform role: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get platform role: %w", err)
	}

	return &role, nil
}

func (r *PostgresRoleAssignmentRepository) CountPlatformAdmins(
	ctx context.Context,
) (int, error) {
	const query = `
		SELECT COUNT(DISTINCT ra.user_id)
		FROM role_assignments ra
		JOIN users u ON u.id = ra.user_id
		JOIN roles r ON r.id = ra.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id AND p.scope = 'platform'
		WHERE ra.tenant_id IS NULL
		  AND u.status = 'active'
		  AND r.scope = 'platform'
		  AND (r.name = 'PLATFORM_ADMIN' OR p.name = 'role.assign')
	`

	var count int
	err := r.db.Pool().QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count platform admins: %w", err)
	}

	return count, nil
}
