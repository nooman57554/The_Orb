package repository_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

func TestPostgresSessionRepository_IsActive_NilUUID(t *testing.T) {
	// A nil UUID should immediately return (false, nil) without requiring DB interaction
	repo := repository.NewPostgresSessionRepository(nil)

	active, err := repo.IsActive(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("expected nil error for nil UUID, got: %v", err)
	}
	if active {
		t.Error("expected active to be false for nil UUID")
	}
}

func TestPostgresSessionRepository_Revoke_NilUUID(t *testing.T) {
	repo := repository.NewPostgresSessionRepository(nil)
	err := repo.Revoke(context.Background(), uuid.Nil)
	if err == nil {
		t.Fatal("expected error for nil UUID in Revoke, got nil")
	}
}

func TestPostgresSessionRepository_RevokeByRefreshTokenHash_Empty(t *testing.T) {
	repo := repository.NewPostgresSessionRepository(nil)
	err := repo.RevokeByRefreshTokenHash(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty token hash in RevokeByRefreshTokenHash, got nil")
	}
}

func TestPostgresSessionRepository_RotateRefreshToken_InvalidInputs(t *testing.T) {
	repo := repository.NewPostgresSessionRepository(nil)

	if _, err := repo.RotateRefreshToken(context.Background(), "", "new"); err == nil {
		t.Fatal("expected error for empty old token hash")
	}

	if _, err := repo.RotateRefreshToken(context.Background(), "old", ""); err == nil {
		t.Fatal("expected error for empty new token hash")
	}

	if _, err := repo.RotateRefreshToken(context.Background(), "same", "same"); err == nil {
		t.Fatal("expected error when old and new token hashes are identical")
	}
}
