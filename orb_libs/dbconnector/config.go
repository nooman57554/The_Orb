package dbconnector

import "time"

type Config struct {
	DatabaseURL string

	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	HealthCheckTime time.Duration
}
