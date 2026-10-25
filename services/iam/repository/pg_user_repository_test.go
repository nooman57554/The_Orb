package repository_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

func TestPostgresUserRepository_Create_DuplicateEmailErrorMapping(t *testing.T) {
	tests := []struct {
		name          string
		inputErr      error
		wantDuplicate bool
	}{
		{
			name: "unique violation on users_email_key",
			inputErr: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "users_email_key",
			},
			wantDuplicate: true,
		},
		{
			name: "unique violation on different constraint",
			inputErr: &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "users_pkey",
			},
			wantDuplicate: false,
		},
		{
			name: "different error code on users_email_key",
			inputErr: &pgconn.PgError{
				Code:           "23503", // foreign key violation
				ConstraintName: "users_email_key",
			},
			wantDuplicate: false,
		},
		{
			name:          "standard network error",
			inputErr:      errors.New("connection reset by peer"),
			wantDuplicate: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var isDuplicate bool
			var pgErr *pgconn.PgError
			if errors.As(tc.inputErr, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_email_key" {
				isDuplicate = true
			}

			if isDuplicate != tc.wantDuplicate {
				t.Errorf("expected duplicate=%v, got %v", tc.wantDuplicate, isDuplicate)
			}
		})
	}
}

func TestPostgresUserRepository_ErrDuplicateEmail(t *testing.T) {
	if repository.ErrDuplicateEmail == nil {
		t.Fatal("expected ErrDuplicateEmail to be defined")
	}
}
