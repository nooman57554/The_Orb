package dbconnector

import (
	"context"
	"testing"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	databaseURL := "postgres://platform:platform@localhost:5432/platform"

	connector, err := New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("failed to create DB connector: %v", err)
	}

	defer connector.Close()

	if connector.Pool() == nil {
		t.Fatal("expected pool to be initialized")
	}
}
