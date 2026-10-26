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

var (
	ErrNotFound       = errors.New("Not Found")
	ErrDuplicateEmail = errors.New("duplicate email: user already exists")
)

type PostgresUserRepository struct {
	db *dbconnector.DBConnector
}

var _ UserRepository = (*PostgresUserRepository)(nil)

func NewPostgresUserRepository(
	db *dbconnector.DBConnector,
) *PostgresUserRepository {
	return &PostgresUserRepository{
		db: db,
	}
}

func (r *PostgresUserRepository) GetByID(
	ctx context.Context,
	id uuid.UUID,
) (*model.User, error) {

	const query = `
		SELECT
			id,
			email,
			password_hash,
			status,
			created_at,
			updated_at
		FROM users
		WHERE id = $1
	`

	var user model.User

	err := r.db.Pool().QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user: %w", ErrNotFound)
		}

		return nil, fmt.Errorf("get user by id: %w", err)
	}

	return &user, nil
}

func (r *PostgresUserRepository) GetByEmail(
	ctx context.Context,
	email string,
) (*model.User, error) {

	const query = `
		SELECT
			id,
			email,
			password_hash,
			status,
			created_at,
			updated_at
		FROM users
		WHERE email = $1
	`

	var user model.User

	err := r.db.Pool().QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user: %w", ErrNotFound)
		}

		return nil, fmt.Errorf("get user by email: %w", err)
	}

	return &user, nil
}

func (r *PostgresUserRepository) Create(
	ctx context.Context,
	user *model.User,
) error {

	if user.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate new user id: %w", err)
		}
		user.ID = id
	}

	const query = `
		INSERT INTO users (
			id,
			email,
			password_hash,
			status
		)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at, updated_at
	`
	err := r.db.Pool().QueryRow(ctx, query, user.ID, user.Email, user.PasswordHash, user.Status).Scan(
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_email_key" {
			return ErrDuplicateEmail
		}
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}

func (r *PostgresUserRepository) Update(
	ctx context.Context,
	user *model.User,
) error {

	const query = `
		UPDATE users
		SET
			email = $1,
			password_hash = $2,
			status = $3
		WHERE id = $4
		RETURNING updated_at
	`

	err := r.db.Pool().QueryRow(
		ctx,
		query,
		user.Email,
		user.PasswordHash,
		user.Status,
		user.ID,
	).Scan(
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("user: %w", ErrNotFound)
		}

		return fmt.Errorf("update user: %w", err)
	}

	return nil
}

func (r *PostgresUserRepository) CreateWithTenantRole(
	ctx context.Context,
	user *model.User,
	tenantID, roleID uuid.UUID,
) error {
	if user == nil {
		return fmt.Errorf("user is required")
	}
	if tenantID == uuid.Nil || roleID == uuid.Nil {
		return fmt.Errorf("tenant ID and role ID are required")
	}
	if user.ID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate new user id: %w", err)
		}
		user.ID = id
	}
	if user.Status == "" {
		user.Status = "active"
	}

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	const insertUserQuery = `
		INSERT INTO users (id, email, password_hash, status)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at, updated_at
	`
	err = tx.QueryRow(ctx, insertUserQuery, user.ID, user.Email, user.PasswordHash, user.Status).Scan(
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_email_key" {
			return ErrDuplicateEmail
		}
		return fmt.Errorf("create user: %w", err)
	}

	const insertAssignmentQuery = `
		INSERT INTO tenant_role_assignments (user_id, tenant_id, role_id)
		VALUES ($1, $2, $3)
	`
	_, err = tx.Exec(ctx, insertAssignmentQuery, user.ID, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("assign tenant role: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}

func (r *PostgresUserRepository) GetByIDInTenant(
	ctx context.Context,
	userID, tenantID uuid.UUID,
) (*model.TenantMemberRecord, error) {
	if userID == uuid.Nil || tenantID == uuid.Nil {
		return nil, fmt.Errorf("member: %w", ErrNotFound)
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
		WHERE tra.user_id = $1
		  AND tra.tenant_id = $2
	`

	var record model.TenantMemberRecord
	err := r.db.Pool().QueryRow(ctx, query, userID, tenantID).Scan(
		&record.UserID,
		&record.Email,
		&record.Status,
		&record.RoleID,
		&record.RoleName,
		&record.RoleScope,
		&record.JoinedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("member: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get tenant member: %w", err)
	}

	return &record, nil
}

func (r *PostgresUserRepository) ListByTenant(
	ctx context.Context,
	tenantID uuid.UUID,
	offset, limit int,
) ([]model.TenantMemberRecord, int, error) {
	if tenantID == uuid.Nil {
		return nil, 0, fmt.Errorf("tenant ID is required")
	}
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	const countQuery = `
		SELECT COUNT(*)
		FROM tenant_role_assignments
		WHERE tenant_id = $1
	`
	var total int
	if err := r.db.Pool().QueryRow(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenant members: %w", err)
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
		WHERE tra.tenant_id = $1
		ORDER BY tra.created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.Pool().Query(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenant members: %w", err)
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
			return nil, 0, fmt.Errorf("scan tenant member: %w", err)
		}
		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows error: %w", err)
	}

	return records, total, nil
}

func (r *PostgresUserRepository) SetStatus(
	ctx context.Context,
	id uuid.UUID,
	status string,
) error {
	if id == uuid.Nil {
		return fmt.Errorf("user ID is required")
	}

	const query = `
		UPDATE users
		SET status = $1
		WHERE id = $2
	`

	res, err := r.db.Pool().Exec(ctx, query, status, id)
	if err != nil {
		return fmt.Errorf("set user status: %w", err)
	}

	if res.RowsAffected() == 0 {
		return fmt.Errorf("user: %w", ErrNotFound)
	}

	return nil
}
