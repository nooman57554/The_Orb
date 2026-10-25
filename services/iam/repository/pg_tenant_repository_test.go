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

	// Update with nil tenant or nil ID returns error directly
	err = repo.Update(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil tenant in Update")
	}

	err = repo.Update(context.Background(), &model.Tenant{ID: uuid.Nil})
	if err == nil {
		t.Fatal("expected error for nil ID in Update")
	}

	// With valid ID but uninitialized DB connector, must report pool error
	_, err = repo.GetByID(context.Background(), uuid.New())
	if err == nil {
		t.Fatal("expected error for uninitialized DB in GetByID")
	}

	err = repo.Update(context.Background(), &model.Tenant{ID: uuid.New(), Name: "test"})
	if err == nil {
		t.Fatal("expected error for uninitialized DB in Update")
	}
}
