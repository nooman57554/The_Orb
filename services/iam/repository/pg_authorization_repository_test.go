package repository_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/nooman57554/The_Orb/services/iam/repository"
)

func TestPostgresAuthorizationRepository_InvalidInputs(t *testing.T) {
	repo := repository.NewPostgresAuthorizationRepository(nil)

	// HasPlatformPermission with nil inputs must return false, nil without accessing db
	allowed, err := repo.HasPlatformPermission(context.Background(), uuid.Nil, "user.read")
	if err != nil {
		t.Fatalf("expected nil error for nil user ID, got: %v", err)
	}
	if allowed {
		t.Error("expected false for nil user ID")
	}

	allowed, err = repo.HasPlatformPermission(context.Background(), uuid.New(), "")
	if err != nil {
		t.Fatalf("expected nil error for empty permission, got: %v", err)
	}
	if allowed {
		t.Error("expected false for empty permission")
	}

	// HasTenantPermission with nil inputs must return false, nil without accessing db
	allowed, err = repo.HasTenantPermission(context.Background(), uuid.Nil, uuid.New(), "tenant.read")
	if err != nil {
		t.Fatalf("expected nil error for nil user ID, got: %v", err)
	}
	if allowed {
		t.Error("expected false for nil user ID")
	}

	allowed, err = repo.HasTenantPermission(context.Background(), uuid.New(), uuid.Nil, "tenant.read")
	if err != nil {
		t.Fatalf("expected nil error for nil tenant ID, got: %v", err)
	}
	if allowed {
		t.Error("expected false for nil tenant ID")
	}

	allowed, err = repo.HasTenantPermission(context.Background(), uuid.New(), uuid.New(), "")
	if err != nil {
		t.Fatalf("expected nil error for empty permission, got: %v", err)
	}
	if allowed {
		t.Error("expected false for empty permission")
	}

	// When valid inputs are provided with nil DB connector, it must report pool error
	_, err = repo.HasPlatformPermission(context.Background(), uuid.New(), "user.read")
	if err == nil {
		t.Error("expected error for uninitialized DB in HasPlatformPermission")
	}

	_, err = repo.HasTenantPermission(context.Background(), uuid.New(), uuid.New(), "tenant.read")
	if err == nil {
		t.Error("expected error for uninitialized DB in HasTenantPermission")
	}
}
