package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
	"github.com/nooman57554/The_Orb/services/iam/model"
)

type PostgresRoleRepository struct {
	db *dbconnector.DBConnector
}

var _ RoleRepository = (*PostgresRoleRepository)(nil)

func NewPostgresRoleRepository(db *dbconnector.DBConnector) *PostgresRoleRepository {
	return &PostgresRoleRepository{db: db}
}

func (r *PostgresRoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Role, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("role: %w", ErrNotFound)
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT id, name, scope, tenant_id, description, created_at, updated_at
		FROM roles
		WHERE id = $1
	`

	var role model.Role
	err := r.db.Pool().QueryRow(ctx, query, id).Scan(
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
			return nil, fmt.Errorf("role: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get role by id: %w", err)
	}

	perms, err := r.GetRolePermissions(ctx, role.ID)
	if err != nil {
		return nil, fmt.Errorf("get role permissions: %w", err)
	}
	role.Permissions = perms

	return &role, nil
}

func (r *PostgresRoleRepository) GetByNameAndScope(
	ctx context.Context,
	name, scope string,
	tenantID *uuid.UUID,
) (*model.Role, error) {
	if name == "" || scope == "" {
		return nil, fmt.Errorf("role: %w", ErrNotFound)
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	var query string
	var args []any

	if tenantID != nil && *tenantID != uuid.Nil {
		query = `
			SELECT id, name, scope, tenant_id, description, created_at, updated_at
			FROM roles
			WHERE name = $1 AND scope = $2 AND tenant_id = $3
		`
		args = []any{name, scope, *tenantID}
	} else {
		query = `
			SELECT id, name, scope, tenant_id, description, created_at, updated_at
			FROM roles
			WHERE name = $1 AND scope = $2 AND tenant_id IS NULL
		`
		args = []any{name, scope}
	}

	var role model.Role
	err := r.db.Pool().QueryRow(ctx, query, args...).Scan(
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
			return nil, fmt.Errorf("role: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get role by name and scope: %w", err)
	}

	perms, err := r.GetRolePermissions(ctx, role.ID)
	if err != nil {
		return nil, fmt.Errorf("get role permissions: %w", err)
	}
	role.Permissions = perms

	return &role, nil
}

func (r *PostgresRoleRepository) ListByTenant(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]model.Role, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT id, name, scope, tenant_id, description, created_at, updated_at
		FROM roles
		WHERE scope = 'system_tenant'
		   OR (scope = 'custom_tenant' AND tenant_id = $1)
		ORDER BY scope ASC, name ASC
	`

	rows, err := r.db.Pool().Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list tenant roles: %w", err)
	}
	defer rows.Close()

	roles := make([]model.Role, 0)
	for rows.Next() {
		var role model.Role
		if err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Scope,
			&role.TenantID,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	for i := range roles {
		perms, err := r.GetRolePermissions(ctx, roles[i].ID)
		if err != nil {
			return nil, fmt.Errorf("get role permissions: %w", err)
		}
		roles[i].Permissions = perms
	}

	return roles, nil
}

func (r *PostgresRoleRepository) ListPlatform(ctx context.Context) ([]model.Role, error) {
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT id, name, scope, tenant_id, description, created_at, updated_at
		FROM roles
		WHERE scope = 'platform'
		ORDER BY name ASC
	`

	rows, err := r.db.Pool().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list platform roles: %w", err)
	}
	defer rows.Close()

	roles := make([]model.Role, 0)
	for rows.Next() {
		var role model.Role
		if err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Scope,
			&role.TenantID,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	for i := range roles {
		perms, err := r.GetRolePermissions(ctx, roles[i].ID)
		if err != nil {
			return nil, fmt.Errorf("get role permissions: %w", err)
		}
		roles[i].Permissions = perms
	}

	return roles, nil
}

func (r *PostgresRoleRepository) CreateCustom(
	ctx context.Context,
	role *model.Role,
	permissionIDs []uuid.UUID,
) error {
	if role == nil {
		return fmt.Errorf("role is required")
	}
	if role.Scope != model.RoleScopeCustomTenant || role.TenantID == nil || *role.TenantID == uuid.Nil {
		return fmt.Errorf("custom role must have custom_tenant scope and valid tenant_id")
	}
	if role.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate role id: %w", err)
		}
		role.ID = id
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const insertRoleQuery = `
		INSERT INTO roles (id, name, scope, tenant_id, description)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING created_at, updated_at
	`
	err = tx.QueryRow(
		ctx,
		insertRoleQuery,
		role.ID,
		role.Name,
		role.Scope,
		role.TenantID,
		role.Description,
	).Scan(&role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateRoleName
		}
		return fmt.Errorf("insert role: %w", err)
	}

	if len(permissionIDs) > 0 {
		const insertPermQuery = `
			INSERT INTO role_permissions (role_id, permission_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING
		`
		for _, permID := range permissionIDs {
			if permID == uuid.Nil {
				continue
			}
			if _, err := tx.Exec(ctx, insertPermQuery, role.ID, permID); err != nil {
				return fmt.Errorf("insert role permission: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (r *PostgresRoleRepository) UpdateCustom(
	ctx context.Context,
	role *model.Role,
	permissionIDs []uuid.UUID,
) error {
	if role == nil || role.ID == uuid.Nil {
		return fmt.Errorf("role is required")
	}
	if role.TenantID == nil || *role.TenantID == uuid.Nil {
		return fmt.Errorf("tenant ID is required")
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const checkQuery = `
		SELECT scope, tenant_id
		FROM roles
		WHERE id = $1
		FOR UPDATE
	`
	var scope string
	var tenantID *uuid.UUID
	err = tx.QueryRow(ctx, checkQuery, role.ID).Scan(&scope, &tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("role: %w", ErrNotFound)
		}
		return fmt.Errorf("check role: %w", err)
	}

	if scope != model.RoleScopeCustomTenant {
		return ErrSystemRoleImmutable
	}
	if tenantID == nil || *tenantID != *role.TenantID {
		return fmt.Errorf("role: %w", ErrNotFound)
	}

	const updateRoleQuery = `
		UPDATE roles
		SET name = $1, description = $2
		WHERE id = $3 AND tenant_id = $4 AND scope = 'custom_tenant'
		RETURNING updated_at
	`
	err = tx.QueryRow(ctx, updateRoleQuery, role.Name, role.Description, role.ID, *role.TenantID).Scan(&role.UpdatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateRoleName
		}
		return fmt.Errorf("update role: %w", err)
	}

	if permissionIDs != nil {
		const deletePermsQuery = `DELETE FROM role_permissions WHERE role_id = $1`
		if _, err := tx.Exec(ctx, deletePermsQuery, role.ID); err != nil {
			return fmt.Errorf("delete old role permissions: %w", err)
		}

		const insertPermQuery = `
			INSERT INTO role_permissions (role_id, permission_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING
		`
		for _, permID := range permissionIDs {
			if permID == uuid.Nil {
				continue
			}
			if _, err := tx.Exec(ctx, insertPermQuery, role.ID, permID); err != nil {
				return fmt.Errorf("insert role permission: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (r *PostgresRoleRepository) DeleteCustom(
	ctx context.Context,
	id, tenantID uuid.UUID,
) error {
	if id == uuid.Nil || tenantID == uuid.Nil {
		return fmt.Errorf("role ID and tenant ID are required")
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const checkQuery = `
		SELECT scope, tenant_id
		FROM roles
		WHERE id = $1
		FOR UPDATE
	`
	var scope string
	var existingTenantID *uuid.UUID
	err = tx.QueryRow(ctx, checkQuery, id).Scan(&scope, &existingTenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("role: %w", ErrNotFound)
		}
		return fmt.Errorf("check role: %w", err)
	}

	if scope != model.RoleScopeCustomTenant {
		return ErrSystemRoleImmutable
	}
	if existingTenantID == nil || *existingTenantID != tenantID {
		return fmt.Errorf("role: %w", ErrNotFound)
	}

	// Check active assignments
	const checkAssignQuery = `
		SELECT EXISTS (
			SELECT 1 FROM tenant_role_assignments WHERE role_id = $1
			UNION
			SELECT 1 FROM platform_role_assignments WHERE role_id = $1
		)
	`
	var hasAssignments bool
	if err := tx.QueryRow(ctx, checkAssignQuery, id).Scan(&hasAssignments); err != nil {
		return fmt.Errorf("check role assignments: %w", err)
	}
	if hasAssignments {
		return ErrRoleHasAssignments
	}

	const deleteQuery = `
		DELETE FROM roles
		WHERE id = $1 AND tenant_id = $2 AND scope = 'custom_tenant'
	`
	res, err := tx.Exec(ctx, deleteQuery, id, tenantID)
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("role: %w", ErrNotFound)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (r *PostgresRoleRepository) HasActiveAssignments(
	ctx context.Context,
	roleID uuid.UUID,
) (bool, error) {
	if roleID == uuid.Nil {
		return false, nil
	}
	if r.db == nil || r.db.Pool() == nil {
		return false, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT EXISTS (
			SELECT 1 FROM tenant_role_assignments WHERE role_id = $1
			UNION
			SELECT 1 FROM platform_role_assignments WHERE role_id = $1
		)
	`
	var exists bool
	if err := r.db.Pool().QueryRow(ctx, query, roleID).Scan(&exists); err != nil {
		return false, fmt.Errorf("check active assignments: %w", err)
	}

	return exists, nil
}

func (r *PostgresRoleRepository) GetRolePermissions(
	ctx context.Context,
	roleID uuid.UUID,
) ([]model.Permission, error) {
	if roleID == uuid.Nil {
		return nil, nil
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT p.id, p.name, p.description, p.created_at
		FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.name ASC
	`

	rows, err := r.db.Pool().Query(ctx, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("get role permissions: %w", err)
	}
	defer rows.Close()

	perms := make([]model.Permission, 0)
	for rows.Next() {
		var p model.Permission
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		perms = append(perms, p)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	return perms, nil
}
