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

type PostgresSessionRepository struct {
	db *dbconnector.DBConnector
}

var _ SessionRepository = (*PostgresSessionRepository)(nil)

func NewPostgresSessionRepository(
	db *dbconnector.DBConnector,
) *PostgresSessionRepository {
	return &PostgresSessionRepository{db: db}
}

func (r *PostgresSessionRepository) Create(
	ctx context.Context,
	session *model.Session,
	tokenHash string,
) error {
	if session.ID == uuid.Nil || session.UserID == uuid.Nil {
		return fmt.Errorf("session ID and user ID are required")
	}
	if tokenHash == "" {
		return fmt.Errorf("refresh token hash is required")
	}

	const query = `
		INSERT INTO sessions (
			id,
			user_id,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3, $4)
		RETURNING created_at
	`

	err := r.db.Pool().QueryRow(
		ctx,
		query,
		session.ID,
		session.UserID,
		tokenHash,
		session.ExpiresAt,
	).Scan(&session.CreatedAt)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	return nil
}

func (r *PostgresSessionRepository) GetByRefreshTokenHash(
	ctx context.Context,
	tokenHash string,
) (*model.Session, error) {

	const query = `
		SELECT id, user_id, expires_at, created_at, revoked_at
		FROM sessions
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`

	var session model.Session

	err := r.db.Pool().QueryRow(ctx, query, tokenHash).Scan(
		&session.ID,
		&session.UserID,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session by refresh token hash: %w", err)
	}

	return &session, nil
}

func (r *PostgresSessionRepository) RotateRefreshToken(
	ctx context.Context,
	oldTokenHash string,
	newTokenHash string,
) (*model.Session, error) {
	if oldTokenHash == "" || newTokenHash == "" {
		return nil, fmt.Errorf("old and new refresh token hashes are required")
	}
	if oldTokenHash == newTokenHash {
		return nil, fmt.Errorf("new refresh token must differ from old token")
	}

	const query = `
		UPDATE sessions
		SET token_hash = $2
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
		RETURNING id, user_id, expires_at, created_at, revoked_at
	`

	var session model.Session

	err := r.db.Pool().QueryRow(
		ctx,
		query,
		oldTokenHash,
		newTokenHash,
	).Scan(
		&session.ID,
		&session.UserID,
		&session.ExpiresAt,
		&session.CreatedAt,
		&session.RevokedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	return &session, nil
}

func (r *PostgresSessionRepository) RevokeByRefreshTokenHash(
	ctx context.Context,
	tokenHash string,
) error {
	if tokenHash == "" {
		return fmt.Errorf("refresh token hash is required")
	}

	const query = `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE token_hash = $1
		  AND revoked_at IS NULL
	`

	tag, err := r.db.Pool().Exec(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	return nil
}
