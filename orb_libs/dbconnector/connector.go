package dbconnector

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DBConnector struct {
	pool *pgxpool.Pool
}

func New(
	ctx context.Context,
	databaseURL string,
) (*DBConnector, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return &DBConnector{
		pool: pool,
	}, nil
}

func (c *DBConnector) Pool() *pgxpool.Pool {
	return c.pool
}

func (c *DBConnector) Close() {
	c.pool.Close()
}
