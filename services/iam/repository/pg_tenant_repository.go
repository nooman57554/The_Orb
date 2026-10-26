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

func (r *PostgresTenantRepository) Create(ctx context.Context, tenant *model.Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is required")
	}
	if tenant.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate tenant id: %w", err)
		}
		tenant.ID = id
	}
	if tenant.Status == "" {
		tenant.Status = "active"
	}

	const query = `
		INSERT INTO tenants (id, name, slug, status)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at, updated_at
	`

	err := r.db.Pool().QueryRow(ctx, query, tenant.ID, tenant.Name, tenant.Slug, tenant.Status).Scan(
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrDuplicateSlug
		}
		return fmt.Errorf("create tenant: %w", err)
	}

	return nil
}

func (r *PostgresTenantRepository) GetBySlug(ctx context.Context, slug string) (*model.Tenant, error) {
	if slug == "" {
		return nil, fmt.Errorf("tenant: %w", ErrNotFound)
	}

	const query = `
		SELECT id, name, slug, status, created_at, updated_at
		FROM tenants
		WHERE slug = $1
	`

	var t model.Tenant
	err := r.db.Pool().QueryRow(ctx, query, slug).Scan(
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
		return nil, fmt.Errorf("get tenant by slug: %w", err)
	}

	return &t, nil
}

func (r *PostgresTenantRepository) List(ctx context.Context, offset, limit int) ([]model.Tenant, int, error) {

	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	const countQuery = `SELECT COUNT(*) FROM tenants`
	var total int
	if err := r.db.Pool().QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	const query = `
		SELECT id, name, slug, status, created_at, updated_at
		FROM tenants
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := r.db.Pool().Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	tenants := make([]model.Tenant, 0)
	for rows.Next() {
		var t model.Tenant
		if err := rows.Scan(
			&t.ID,
			&t.Name,
			&t.Slug,
			&t.Status,
			&t.CreatedAt,
			&t.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, t)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows error: %w", err)
	}

	return tenants, total, nil
}

func (r *PostgresTenantRepository) Update(ctx context.Context, tenant *model.Tenant) error {
	if tenant == nil || tenant.ID == uuid.Nil {
		return fmt.Errorf("tenant is required")
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

func (r *PostgresTenantRepository) SetStatus(ctx context.Context, id uuid.UUID, status string) error {
	if id == uuid.Nil {
		return fmt.Errorf("tenant id is required")
	}

	const query = `
		UPDATE tenants
		SET status = $1
		WHERE id = $2
	`

	res, err := r.db.Pool().Exec(ctx, query, status, id)
	if err != nil {
		return fmt.Errorf("set tenant status: %w", err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("tenant: %w", ErrNotFound)
	}

	return nil
}
