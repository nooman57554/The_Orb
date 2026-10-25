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

type PostgresTenantRepository struct {
	db *dbconnector.DBConnector
}

var _ TenantRepository = (*PostgresTenantRepository)(nil)

func NewPostgresTenantRepository(db *dbconnector.DBConnector) *PostgresTenantRepository {
	return &PostgresTenantRepository{db: db}
}

func (r *PostgresTenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*model.Tenant, error) {
	if id == uuid.Nil {
		return nil, fmt.Errorf("tenant: %w", ErrNotFound)
	}
	if r.db == nil || r.db.Pool() == nil {
		return nil, fmt.Errorf("database pool not initialized")
	}

	const query = `
		SELECT id, name, slug, status, created_at, updated_at
		FROM tenants
		WHERE id = $1
	`

	var t model.Tenant
	err := r.db.Pool().QueryRow(ctx, query, id).Scan(
		&t.ID,
		&t.Name,
		&t.Slug,
		&t.Status,
		&t.CreatedAt,
		&t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("tenant: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get tenant by id: %w", err)
	}

	return &t, nil
}

func (r *PostgresTenantRepository) Update(ctx context.Context, tenant *model.Tenant) error {
	if tenant == nil || tenant.ID == uuid.Nil {
		return fmt.Errorf("tenant is required")
	}
	if r.db == nil || r.db.Pool() == nil {
		return fmt.Errorf("database pool not initialized")
	}

	const query = `
		UPDATE tenants
		SET name = $1, status = $2
		WHERE id = $3
	`

	res, err := r.db.Pool().Exec(ctx, query, tenant.Name, tenant.Status, tenant.ID)
	if err != nil {
		return fmt.Errorf("update tenant: %w", err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("tenant: %w", ErrNotFound)
	}

	return nil
}
