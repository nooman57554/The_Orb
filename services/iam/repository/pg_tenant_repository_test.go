package repository_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/model"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

func TestPostgresTenantRepository_InvalidInputs(t *testing.T) {
	repo := repository.NewPostgresTenantRepository(nil)

	// GetByID with nil UUID returns ErrNotFound directly
	_, err := repo.GetByID(context.Background(), uuid.Nil)
	if err == nil {
		t.Fatal("expected error for nil UUID in GetByID")
	}

	// GetBySlug with empty slug returns ErrNotFound directly
	_, err = repo.GetBySlug(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty slug in GetBySlug")
	}

	// Update with nil tenant or nil ID returns error directly
	err = repo.Update(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil tenant in Update")
	}

	err = repo.Update(context.Background(), &model.Tenant{ID: uuid.Nil})
	if err == nil {
		t.Fatal("expected error for nil ID in Update")
	}

	// SetStatus with nil ID returns error directly
	err = repo.SetStatus(context.Background(), uuid.Nil, "active")
	if err == nil {
		t.Fatal("expected error for nil ID in SetStatus")
	}

	// Create with nil tenant returns error directly
	err = repo.Create(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil tenant in Create")
	}
}
