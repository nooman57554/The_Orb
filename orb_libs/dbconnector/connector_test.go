package dbconnector

import (
	"context"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	databaseURL := "postgres://platform:platform@localhost:5432/platform"
	config := Config{
		DatabaseURL:     databaseURL,
		MaxConns:        10,
		MinConns:        2,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
		HealthCheckTime: 1 * time.Minute,
	}

	connector, err := New(ctx, config)
	if err != nil {
		t.Fatalf("failed to create DB connector: %v", err)
	}

	defer connector.Close()

	if connector.Pool() == nil {
		t.Fatal("expected pool to be initialized")
	}
}
