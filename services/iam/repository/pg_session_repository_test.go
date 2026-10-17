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
