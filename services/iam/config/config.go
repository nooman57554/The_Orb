package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
	"github.com/nooman57554/The_Orb/orb_libs/identity/keyloader"
)

// Config holds all validated runtime configuration for the IAM service.
type Config struct {
	// HTTP Server settings
	HTTPAddr         string
	HTTPReadTimeout  time.Duration
	HTTPWriteTimeout time.Duration
	HTTPIdleTimeout  time.Duration

	// Database settings
	DatabaseURL       string
	DBMaxConns        int32
	DBMinConns        int32
	DBMaxConnLifetime time.Duration
	DBMaxConnIdleTime time.Duration
	DBHealthCheckTime time.Duration

	// JWT and session settings
	JWTPrivateKeyPath string
	JWTPublicKeysDir  string
	JWTKeyID          string
	JWTIssuer         string
	JWTAudience       string
	JWTTTL            time.Duration
	RefreshTokenTTL   time.Duration
}

// DatabaseConfig converts Config into a dbconnector.Config for database pool creation.
func (c Config) DatabaseConfig() dbconnector.Config {
	return dbconnector.Config{
		DatabaseURL:     c.DatabaseURL,
		MaxConns:        c.DBMaxConns,
		MinConns:        c.DBMinConns,
		MaxConnLifetime: c.DBMaxConnLifetime,
		MaxConnIdleTime: c.DBMaxConnIdleTime,
		HealthCheckTime: c.DBHealthCheckTime,
	}
}

// RedactedDatabaseURL returns the database URL with any password replaced by asterisks.
func (c Config) RedactedDatabaseURL() string {
	return RedactDatabaseURL(c.DatabaseURL)
}

// RedactDatabaseURL masks the password in a connection string URL, safe for logging.
func RedactDatabaseURL(rawURL string) string {
	if strings.TrimSpace(rawURL) == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[redacted-database-url]"
	}
	if u.User != nil {
		if _, hasPass := u.User.Password(); hasPass {
			u.User = url.UserPassword(u.User.Username(), "REDACTED")
		}
	}
	return u.String()
}

// Load reads and validates configuration from the environment using os.Getenv.
func Load() (Config, error) {
	return LoadFromLookup(os.Getenv)
}

// LoadFromLookup reads and validates configuration using a custom lookup function.
func LoadFromLookup(lookup func(string) string) (Config, error) {
	if lookup == nil {
		lookup = os.Getenv
	}

	getEnv := func(key, defaultValue string) string {
		v := strings.TrimSpace(lookup(key))
		if v == "" {
			return defaultValue
		}
		return v
	}

	getDuration := func(key string, defaultValue time.Duration) (time.Duration, error) {
		val := strings.TrimSpace(lookup(key))
		if val == "" {
			return defaultValue, nil
		}
		d, err := time.ParseDuration(val)
		if err != nil || d <= 0 {
			return 0, fmt.Errorf("%s must be a positive duration", key)
		}
		return d, nil
	}

	getInt32 := func(key string, defaultValue int32) (int32, error) {
		val := strings.TrimSpace(lookup(key))
		if val == "" {
			return defaultValue, nil
		}
		i, err := strconv.ParseInt(val, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("%s must be a valid integer", key)
		}
		return int32(i), nil
	}

	// 1. HTTP Server configuration
	httpAddr := getEnv("ORB_IAM_HTTP_ADDR", ":8080")
	if !strings.Contains(httpAddr, ":") {
		if _, err := strconv.Atoi(httpAddr); err == nil {
			httpAddr = ":" + httpAddr
		}
	}
	_, portStr, err := net.SplitHostPort(httpAddr)
	if err != nil {
		return Config{}, fmt.Errorf("ORB_IAM_HTTP_ADDR is invalid: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return Config{}, fmt.Errorf("ORB_IAM_HTTP_ADDR port must be between 1 and 65535")
	}

	readTimeout, err := getDuration("ORB_IAM_HTTP_READ_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}
	writeTimeout, err := getDuration("ORB_IAM_HTTP_WRITE_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}
	idleTimeout, err := getDuration("ORB_IAM_HTTP_IDLE_TIMEOUT", 60*time.Second)
	if err != nil {
		return Config{}, err
	}

	// 2. Database configuration
	dbURL := strings.TrimSpace(lookup("ORB_IAM_DATABASE_URL"))
	if dbURL == "" {
		return Config{}, fmt.Errorf("ORB_IAM_DATABASE_URL is required")
	}
	// Parse without logging raw connection string to avoid leaking secrets
	if _, err := pgxpool.ParseConfig(dbURL); err != nil {
		return Config{}, fmt.Errorf("ORB_IAM_DATABASE_URL is invalid: failed to parse connection string")
	}

	maxConns, err := getInt32("ORB_IAM_DB_MAX_CONNS", 10)
	if err != nil {
		return Config{}, err
	}
	if maxConns <= 0 {
		return Config{}, fmt.Errorf("ORB_IAM_DB_MAX_CONNS must be greater than 0")
	}

	minConns, err := getInt32("ORB_IAM_DB_MIN_CONNS", 2)
	if err != nil {
		return Config{}, err
	}
	if minConns < 0 {
		return Config{}, fmt.Errorf("ORB_IAM_DB_MIN_CONNS cannot be negative")
	}
	if minConns > maxConns {
		return Config{}, fmt.Errorf("ORB_IAM_DB_MIN_CONNS (%d) cannot exceed ORB_IAM_DB_MAX_CONNS (%d)", minConns, maxConns)
	}

	dbMaxLifetime, err := getDuration("ORB_IAM_DB_MAX_CONN_LIFETIME", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	dbMaxIdle, err := getDuration("ORB_IAM_DB_MAX_CONN_IDLE_TIME", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}
	dbHealthCheck, err := getDuration("ORB_IAM_DB_HEALTH_CHECK_TIME", 1*time.Minute)
	if err != nil {
		return Config{}, err
	}

	// 3. JWT & Keyloader configuration
	privKeyPath := strings.TrimSpace(lookup("ORB_IAM_JWT_PRIVATE_KEY_PATH"))
	if privKeyPath == "" {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_PRIVATE_KEY_PATH is required")
	}
	privFi, err := os.Stat(privKeyPath)
	if err != nil {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_PRIVATE_KEY_PATH is unusable: %w", err)
	}
	if privFi.IsDir() {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_PRIVATE_KEY_PATH is unusable: path is a directory, expected a file")
	}

	pubKeysDir := strings.TrimSpace(lookup("ORB_IAM_JWT_PUBLIC_KEYS_DIR"))
	if pubKeysDir == "" {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_PUBLIC_KEYS_DIR is required")
	}
	pubFi, err := os.Stat(pubKeysDir)
	if err != nil {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_PUBLIC_KEYS_DIR is unusable: %w", err)
	}
	if !pubFi.IsDir() {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_PUBLIC_KEYS_DIR is unusable: path is not a directory")
	}

	keyID := strings.TrimSpace(lookup("ORB_IAM_JWT_ACTIVE_KEY_ID"))
	if keyID == "" {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_ACTIVE_KEY_ID is required")
	}
	if !keyloader.ValidKeyID(keyID) {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_ACTIVE_KEY_ID is invalid")
	}

	issuer := strings.TrimSpace(lookup("ORB_IAM_JWT_ISSUER"))
	if issuer == "" {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_ISSUER is required")
	}
	if !validPrintableASCII(issuer) {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_ISSUER is invalid: contains unprintable characters")
	}

	audience := strings.TrimSpace(lookup("ORB_IAM_JWT_AUDIENCE"))
	if audience == "" {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_AUDIENCE is required")
	}
	if !validPrintableASCII(audience) {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_AUDIENCE is invalid: contains unprintable characters")
	}

	jwtTTL, err := getDuration("ORB_IAM_JWT_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}

	refreshTTL, err := getDuration("ORB_IAM_REFRESH_TOKEN_TTL", 720*time.Hour)
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTPAddr:         httpAddr,
		HTTPReadTimeout:  readTimeout,
		HTTPWriteTimeout: writeTimeout,
		HTTPIdleTimeout:  idleTimeout,

		DatabaseURL:       dbURL,
		DBMaxConns:        maxConns,
		DBMinConns:        minConns,
		DBMaxConnLifetime: dbMaxLifetime,
		DBMaxConnIdleTime: dbMaxIdle,
		DBHealthCheckTime: dbHealthCheck,

		JWTPrivateKeyPath: privKeyPath,
		JWTPublicKeysDir:  pubKeysDir,
		JWTKeyID:          keyID,
		JWTIssuer:         issuer,
		JWTAudience:       audience,
		JWTTTL:            jwtTTL,
		RefreshTokenTTL:   refreshTTL,
	}, nil
}

func validPrintableASCII(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
