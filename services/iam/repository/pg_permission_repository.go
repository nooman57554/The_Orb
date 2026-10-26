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

type PostgresPermissionRepository struct {
	db *dbconnector.DBConnector
}

var _ PermissionRepository = (*PostgresPermissionRepository)(nil)

func NewPostgresPermissionRepository(db *dbconnector.DBConnector) *PostgresPermissionRepository {
	return &PostgresPermissionRepository{db: db}
}

func (r *PostgresPermissionRepository) ListAll(ctx context.Context) ([]model.Permission, error) {
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT id, name, description, created_at
		FROM permissions
		ORDER BY name ASC
	`

	rows, err := r.db.Pool().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list all permissions: %w", err)
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

func (r *PostgresPermissionRepository) GetByIDs(
	ctx context.Context,
	ids []uuid.UUID,
) ([]model.Permission, error) {
	if len(ids) == 0 {
		return []model.Permission{}, nil
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT id, name, description, created_at
		FROM permissions
		WHERE id = ANY($1)
		ORDER BY name ASC
	`

	rows, err := r.db.Pool().Query(ctx, query, ids)
	if err != nil {
		return nil, fmt.Errorf("get permissions by ids: %w", err)
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

func (r *PostgresPermissionRepository) GetByName(
	ctx context.Context,
	name string,
) (*model.Permission, error) {
	if name == "" {
		return nil, fmt.Errorf("permission: %w", ErrNotFound)
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT id, name, description, created_at
		FROM permissions
		WHERE name = $1
	`

	var p model.Permission
	err := r.db.Pool().QueryRow(ctx, query, name).Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("permission: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get permission by name: %w", err)
	}

	return &p, nil
}
