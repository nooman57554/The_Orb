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

var ErrNotFound = errors.New("Not Found")

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
