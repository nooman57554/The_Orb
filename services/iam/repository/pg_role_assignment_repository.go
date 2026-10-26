package repository

import (
	"context"
	"fmt"

	"github.com/google/uuid"
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
	if r.db == nil || r.db.Pool() == nil {
		return fmt.Errorf("database pool not initialized")
	}

	const query = `
		INSERT INTO tenant_role_assignments (user_id, tenant_id, role_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, tenant_id)
		DO UPDATE SET role_id = EXCLUDED.role_id
	`

	_, err := r.db.Pool().Exec(ctx, query, userID, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("assign tenant role: %w", err)
	}

	return nil
}

func (r *PostgresRoleAssignmentRepository) RemoveTenantRole(
	ctx context.Context,
	userID, tenantID uuid.UUID,
) error {
	if userID == uuid.Nil || tenantID == uuid.Nil {
		return fmt.Errorf("user ID and tenant ID are required")
	}
	if r.db == nil || r.db.Pool() == nil {
		return fmt.Errorf("database pool not initialized")
	}

	const query = `
		DELETE FROM tenant_role_assignments
		WHERE user_id = $1 AND tenant_id = $2
	`

	res, err := r.db.Pool().Exec(ctx, query, userID, tenantID)
	if err != nil {
		return fmt.Errorf("remove tenant role: %w", err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("membership: %w", ErrNotFound)
	}

	return nil
}

func (r *PostgresRoleAssignmentRepository) ListUsersByTenantRole(
	ctx context.Context,
	tenantID, roleID uuid.UUID,
) ([]model.TenantMemberRecord, error) {
	if tenantID == uuid.Nil || roleID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID and role ID are required")
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT
			u.id,
			u.email,
			u.status,
			r.id,
			r.name,
			r.scope,
			tra.created_at
		FROM tenant_role_assignments tra
		JOIN users u ON u.id = tra.user_id
		JOIN roles r ON r.id = tra.role_id
		WHERE tra.tenant_id = $1 AND tra.role_id = $2
		ORDER BY tra.created_at DESC
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
	if r.db == nil || r.db.Pool() == nil {
		return fmt.Errorf("database pool not initialized")
	}

	const query = `
		INSERT INTO platform_role_assignments (user_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (user_id)
		DO UPDATE SET role_id = EXCLUDED.role_id
	`

	_, err := r.db.Pool().Exec(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("assign platform role: %w", err)
	}

	return nil
}

func (r *PostgresRoleAssignmentRepository) RemovePlatformRole(
	ctx context.Context,
	userID uuid.UUID,
) error {
	if userID == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}
	if r.db == nil || r.db.Pool() == nil {
		return fmt.Errorf("database pool not initialized")
	}

	const query = `
		DELETE FROM platform_role_assignments
		WHERE user_id = $1
	`

	res, err := r.db.Pool().Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("remove platform role: %w", err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("platform role assignment: %w", ErrNotFound)
	}

	return nil
}

func (r *PostgresRoleAssignmentRepository) CountPlatformAdmins(
	ctx context.Context,
) (int, error) {
	if r.db == nil || r.db.Pool() == nil {
		return 0, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT COUNT(*)
		FROM platform_role_assignments pra
		JOIN users u ON u.id = pra.user_id
		JOIN roles r ON r.id = pra.role_id
		WHERE u.status = 'active'
		  AND r.scope = 'platform'
		  AND r.name = 'PLATFORM_ADMIN'
	`

	var count int
	err := r.db.Pool().QueryRow(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count platform admins: %w", err)
	}

	return count, nil
}
