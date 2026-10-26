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

	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate assignment id: %w", err)
	}

	const query = `
		INSERT INTO role_assignments (id, user_id, tenant_id, role_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, tenant_id) WHERE tenant_id IS NOT NULL
		DO UPDATE SET role_id = EXCLUDED.role_id, created_at = NOW()
	`

	_, err = r.db.Pool().Exec(ctx, query, id, userID, tenantID, roleID)
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

	const query = `
		DELETE FROM role_assignments
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

	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate assignment id: %w", err)
	}

	const query = `
		INSERT INTO role_assignments (id, user_id, tenant_id, role_id)
		VALUES ($1, $2, NULL, $3)
		ON CONFLICT (user_id) WHERE tenant_id IS NULL
		DO UPDATE SET role_id = EXCLUDED.role_id, created_at = NOW()
	`

	_, err = r.db.Pool().Exec(ctx, query, id, userID, roleID)
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

	const query = `
		DELETE FROM role_assignments
		WHERE user_id = $1 AND tenant_id IS NULL
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
		SELECT COUNT(*)
		FROM role_assignments ra
		JOIN users u ON u.id = ra.user_id
		JOIN roles r ON r.id = ra.role_id
		WHERE ra.tenant_id IS NULL
		  AND u.status = 'active'
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
