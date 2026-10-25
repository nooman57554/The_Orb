package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nooman57554/The_Orb/services/iam/config"
)

// setupValidEnvironment creates temporary key files/dirs and returns a map
// of valid environment variables.
func setupValidEnvironment(t *testing.T) map[string]string {
	t.Helper()

	tempDir := t.TempDir()
	privKeyPath := filepath.Join(tempDir, "private.pem")
	if err := os.WriteFile(privKeyPath, []byte("fake-ed25519-pem"), 0600); err != nil {
		t.Fatalf("write fake private key: %v", err)
	}

	pubKeysDir := filepath.Join(tempDir, "public")
	if err := os.Mkdir(pubKeysDir, 0700); err != nil {
		t.Fatalf("create fake public keys dir: %v", err)
	}

	return map[string]string{
		"ORB_IAM_HTTP_ADDR":                  ":8080",
		"ORB_IAM_HTTP_READ_TIMEOUT":          "10s",
		"ORB_IAM_HTTP_WRITE_TIMEOUT":         "10s",
		"ORB_IAM_HTTP_IDLE_TIMEOUT":          "30s",
		"ORB_IAM_DATABASE_URL":               "postgres://user:secret@localhost:5432/orb_db?sslmode=disable",
		"ORB_IAM_DB_MAX_CONNS":               "20",
		"ORB_IAM_DB_MIN_CONNS":               "5",
		"ORB_IAM_DB_MAX_CONN_LIFETIME":       "1h",
		"ORB_IAM_DB_MAX_CONN_IDLE_TIME":      "10m",
		"ORB_IAM_DB_HEALTH_CHECK_TIME":       "2m",
		"ORB_IAM_JWT_PRIVATE_KEY_PATH":       privKeyPath,
		"ORB_IAM_JWT_PUBLIC_KEYS_DIR":        pubKeysDir,
		"ORB_IAM_JWT_ACTIVE_KEY_ID":          "key-2026-01",
		"ORB_IAM_JWT_ISSUER":                 "orb-iam",
		"ORB_IAM_JWT_AUDIENCE":               "orb-platform",
		"ORB_IAM_JWT_TTL":                    "15m",
		"ORB_IAM_REFRESH_TOKEN_TTL":          "168h",
		"ORB_IAM_REFRESH_REUSE_GRACE_PERIOD": "30s",
	}
}

func lookupFromMap(env map[string]string) func(string) string {
	return func(key string) string {
		return env[key]
	}
}

func TestLoad_ValidFullConfig(t *testing.T) {
	env := setupValidEnvironment(t)

	cfg, err := config.LoadFromLookup(lookupFromMap(env))
	if err != nil {
		t.Fatalf("expected valid config to load, got: %v", err)
	}

	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %v, want :8080", cfg.HTTPAddr)
	}
	if cfg.HTTPReadTimeout != 10*time.Second {
		t.Errorf("HTTPReadTimeout = %v, want 10s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPWriteTimeout != 10*time.Second {
		t.Errorf("HTTPWriteTimeout = %v, want 10s", cfg.HTTPWriteTimeout)
	}
	if cfg.HTTPIdleTimeout != 30*time.Second {
		t.Errorf("HTTPIdleTimeout = %v, want 30s", cfg.HTTPIdleTimeout)
	}
	if cfg.DatabaseURL != env["ORB_IAM_DATABASE_URL"] {
		t.Errorf("DatabaseURL mismatch")
	}
	if cfg.DBMaxConns != 20 {
		t.Errorf("DBMaxConns = %v, want 20", cfg.DBMaxConns)
	}
	if cfg.DBMinConns != 5 {
		t.Errorf("DBMinConns = %v, want 5", cfg.DBMinConns)
	}
	if cfg.DBMaxConnLifetime != 1*time.Hour {
		t.Errorf("DBMaxConnLifetime = %v, want 1h", cfg.DBMaxConnLifetime)
	}
	if cfg.DBMaxConnIdleTime != 10*time.Minute {
		t.Errorf("DBMaxConnIdleTime = %v, want 10m", cfg.DBMaxConnIdleTime)
	}
	if cfg.DBHealthCheckTime != 2*time.Minute {
		t.Errorf("DBHealthCheckTime = %v, want 2m", cfg.DBHealthCheckTime)
	}
	if cfg.JWTKeyID != "key-2026-01" {
		t.Errorf("JWTKeyID = %v, want key-2026-01", cfg.JWTKeyID)
	}
	if cfg.JWTIssuer != "orb-iam" {
		t.Errorf("JWTIssuer = %v, want orb-iam", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != "orb-platform" {
		t.Errorf("JWTAudience = %v, want orb-platform", cfg.JWTAudience)
	}
	if cfg.JWTTTL != 15*time.Minute {
		t.Errorf("JWTTTL = %v, want 15m", cfg.JWTTTL)
	}
	if cfg.RefreshTokenTTL != 168*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 168h", cfg.RefreshTokenTTL)
	}
	if cfg.RefreshReuseGracePeriod != 30*time.Second {
		t.Errorf("RefreshReuseGracePeriod = %v, want 30s", cfg.RefreshReuseGracePeriod)
	}

	// Verify DatabaseConfig() helper
	dbCfg := cfg.DatabaseConfig()
	if dbCfg.DatabaseURL != cfg.DatabaseURL || dbCfg.MaxConns != 20 || dbCfg.MinConns != 5 {
		t.Errorf("DatabaseConfig() fields mismatch: %+v", dbCfg)
	}
}

func TestLoad_ValidDefaults(t *testing.T) {
	baseEnv := setupValidEnvironment(t)

	// Keep only required variables
	minimalEnv := map[string]string{
		"ORB_IAM_DATABASE_URL":         baseEnv["ORB_IAM_DATABASE_URL"],
		"ORB_IAM_JWT_PRIVATE_KEY_PATH": baseEnv["ORB_IAM_JWT_PRIVATE_KEY_PATH"],
		"ORB_IAM_JWT_PUBLIC_KEYS_DIR":  baseEnv["ORB_IAM_JWT_PUBLIC_KEYS_DIR"],
		"ORB_IAM_JWT_ACTIVE_KEY_ID":    baseEnv["ORB_IAM_JWT_ACTIVE_KEY_ID"],
		"ORB_IAM_JWT_ISSUER":           baseEnv["ORB_IAM_JWT_ISSUER"],
		"ORB_IAM_JWT_AUDIENCE":         baseEnv["ORB_IAM_JWT_AUDIENCE"],
	}

	cfg, err := config.LoadFromLookup(lookupFromMap(minimalEnv))
	if err != nil {
		t.Fatalf("expected defaults to load successfully, got: %v", err)
	}

	// Check default values
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("default HTTPAddr = %v, want :8080", cfg.HTTPAddr)
	}
	if cfg.HTTPReadTimeout != 15*time.Second {
		t.Errorf("default HTTPReadTimeout = %v, want 15s", cfg.HTTPReadTimeout)
	}
	if cfg.HTTPWriteTimeout != 15*time.Second {
		t.Errorf("default HTTPWriteTimeout = %v, want 15s", cfg.HTTPWriteTimeout)
	}
	if cfg.HTTPIdleTimeout != 60*time.Second {
		t.Errorf("default HTTPIdleTimeout = %v, want 60s", cfg.HTTPIdleTimeout)
	}
	if cfg.DBMaxConns != 10 {
		t.Errorf("default DBMaxConns = %v, want 10", cfg.DBMaxConns)
	}
	if cfg.DBMinConns != 2 {
		t.Errorf("default DBMinConns = %v, want 2", cfg.DBMinConns)
	}
	if cfg.DBMaxConnLifetime != 30*time.Minute {
		t.Errorf("default DBMaxConnLifetime = %v, want 30m", cfg.DBMaxConnLifetime)
	}
	if cfg.DBMaxConnIdleTime != 5*time.Minute {
		t.Errorf("default DBMaxConnIdleTime = %v, want 5m", cfg.DBMaxConnIdleTime)
	}
	if cfg.DBHealthCheckTime != 1*time.Minute {
		t.Errorf("default DBHealthCheckTime = %v, want 1m", cfg.DBHealthCheckTime)
	}
	if cfg.JWTTTL != 10*time.Minute {
		t.Errorf("default JWTTTL = %v, want 10m", cfg.JWTTTL)
	}
	if cfg.RefreshTokenTTL != 720*time.Hour {
		t.Errorf("default RefreshTokenTTL = %v, want 720h", cfg.RefreshTokenTTL)
	}
	if cfg.RefreshReuseGracePeriod != 15*time.Second {
		t.Errorf("default RefreshReuseGracePeriod = %v, want 15s", cfg.RefreshReuseGracePeriod)
	}
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	requiredFields := []string{
		"ORB_IAM_DATABASE_URL",
		"ORB_IAM_JWT_PRIVATE_KEY_PATH",
		"ORB_IAM_JWT_PUBLIC_KEYS_DIR",
		"ORB_IAM_JWT_ACTIVE_KEY_ID",
		"ORB_IAM_JWT_ISSUER",
		"ORB_IAM_JWT_AUDIENCE",
	}

	for _, field := range requiredFields {
		t.Run("missing_"+field, func(t *testing.T) {
			env := setupValidEnvironment(t)
			delete(env, field)

			_, err := config.LoadFromLookup(lookupFromMap(env))
			if err == nil {
				t.Fatalf("expected error for missing %s, got nil", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error %q should mention missing field %q", err.Error(), field)
			}
		})

		t.Run("empty_"+field, func(t *testing.T) {
			env := setupValidEnvironment(t)
			env[field] = "   "

			_, err := config.LoadFromLookup(lookupFromMap(env))
			if err == nil {
				t.Fatalf("expected error for empty %s, got nil", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error %q should mention empty field %q", err.Error(), field)
			}
		})
	}
}

func TestLoad_MalformedValues(t *testing.T) {
	tests := []struct {
		name          string
		modifyEnv     func(env map[string]string)
		wantErrSubstr string
	}{
		{
			name: "malformed database url",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_DATABASE_URL"] = "not_a_valid_postgres_url://:/"
			},
			wantErrSubstr: "ORB_IAM_DATABASE_URL is invalid",
		},
		{
			name: "invalid active key ID containing dot",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_JWT_ACTIVE_KEY_ID"] = "."
			},
			wantErrSubstr: "ORB_IAM_JWT_ACTIVE_KEY_ID is invalid",
		},
		{
			name: "invalid active key ID containing slashes",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_JWT_ACTIVE_KEY_ID"] = "keys/active-key"
			},
			wantErrSubstr: "ORB_IAM_JWT_ACTIVE_KEY_ID is invalid",
		},
		{
			name: "invalid issuer containing newlines",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_JWT_ISSUER"] = "orb-iam\ninjection"
			},
			wantErrSubstr: "ORB_IAM_JWT_ISSUER is invalid",
		},
		{
			name: "invalid audience containing control characters",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_JWT_AUDIENCE"] = "orb-platform\x00"
			},
			wantErrSubstr: "ORB_IAM_JWT_AUDIENCE is invalid",
		},
		{
			name: "invalid http address missing port",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_HTTP_ADDR"] = "notanaddress"
			},
			wantErrSubstr: "ORB_IAM_HTTP_ADDR is invalid",
		},
		{
			name: "invalid http address port out of range",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_HTTP_ADDR"] = ":70000"
			},
			wantErrSubstr: "ORB_IAM_HTTP_ADDR port must be between 1 and 65535",
		},
		{
			name: "malformed jwt ttl",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_JWT_TTL"] = "invalid-duration"
			},
			wantErrSubstr: "ORB_IAM_JWT_TTL must be a positive duration",
		},
		{
			name: "negative jwt ttl",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_JWT_TTL"] = "-5m"
			},
			wantErrSubstr: "ORB_IAM_JWT_TTL must be a positive duration",
		},
		{
			name: "malformed refresh token ttl",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_REFRESH_TOKEN_TTL"] = "0s"
			},
			wantErrSubstr: "ORB_IAM_REFRESH_TOKEN_TTL must be a positive duration",
		},
		{
			name: "malformed refresh reuse grace period zero",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_REFRESH_REUSE_GRACE_PERIOD"] = "0s"
			},
			wantErrSubstr: "ORB_IAM_REFRESH_REUSE_GRACE_PERIOD must be a positive duration",
		},
		{
			name: "negative refresh reuse grace period",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_REFRESH_REUSE_GRACE_PERIOD"] = "-10s"
			},
			wantErrSubstr: "ORB_IAM_REFRESH_REUSE_GRACE_PERIOD must be a positive duration",
		},
		{
			name: "invalid refresh reuse grace period format",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_REFRESH_REUSE_GRACE_PERIOD"] = "invalid-period"
			},
			wantErrSubstr: "ORB_IAM_REFRESH_REUSE_GRACE_PERIOD must be a positive duration",
		},
		{
			name: "db max conns zero",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_DB_MAX_CONNS"] = "0"
			},
			wantErrSubstr: "ORB_IAM_DB_MAX_CONNS must be greater than 0",
		},
		{
			name: "db min conns negative",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_DB_MIN_CONNS"] = "-1"
			},
			wantErrSubstr: "ORB_IAM_DB_MIN_CONNS cannot be negative",
		},
		{
			name: "db min conns exceeds max conns",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_DB_MAX_CONNS"] = "5"
				env["ORB_IAM_DB_MIN_CONNS"] = "10"
			},
			wantErrSubstr: "cannot exceed ORB_IAM_DB_MAX_CONNS",
		},
		{
			name: "malformed read timeout",
			modifyEnv: func(env map[string]string) {
				env["ORB_IAM_HTTP_READ_TIMEOUT"] = "bad"
			},
			wantErrSubstr: "ORB_IAM_HTTP_READ_TIMEOUT must be a positive duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupValidEnvironment(t)
			tt.modifyEnv(env)

			_, err := config.LoadFromLookup(lookupFromMap(env))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error %q does not contain expected substring %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}

func TestLoad_UnusableKeyPaths(t *testing.T) {
	t.Run("private key file does not exist", func(t *testing.T) {
		env := setupValidEnvironment(t)
		env["ORB_IAM_JWT_PRIVATE_KEY_PATH"] = filepath.Join(t.TempDir(), "nonexistent.pem")

		_, err := config.LoadFromLookup(lookupFromMap(env))
		if err == nil {
			t.Fatal("expected error for nonexistent private key, got nil")
		}
		if !strings.Contains(err.Error(), "ORB_IAM_JWT_PRIVATE_KEY_PATH is unusable") {
			t.Errorf("expected unusable private key error, got: %v", err)
		}
	})

	t.Run("private key path is a directory", func(t *testing.T) {
		env := setupValidEnvironment(t)
		env["ORB_IAM_JWT_PRIVATE_KEY_PATH"] = t.TempDir()

		_, err := config.LoadFromLookup(lookupFromMap(env))
		if err == nil {
			t.Fatal("expected error when private key path is directory, got nil")
		}
		if !strings.Contains(err.Error(), "path is not a regular file") {
			t.Errorf("expected not a regular file error, got: %v", err)
		}
	})

	t.Run("public keys dir does not exist", func(t *testing.T) {
		env := setupValidEnvironment(t)
		env["ORB_IAM_JWT_PUBLIC_KEYS_DIR"] = filepath.Join(t.TempDir(), "nonexistent_dir")

		_, err := config.LoadFromLookup(lookupFromMap(env))
		if err == nil {
			t.Fatal("expected error for nonexistent public keys dir, got nil")
		}
		if !strings.Contains(err.Error(), "ORB_IAM_JWT_PUBLIC_KEYS_DIR is unusable") {
			t.Errorf("expected unusable public keys dir error, got: %v", err)
		}
	})

	t.Run("public keys dir is a file", func(t *testing.T) {
		env := setupValidEnvironment(t)
		filePath := filepath.Join(t.TempDir(), "file.txt")
		_ = os.WriteFile(filePath, []byte("test"), 0600)
		env["ORB_IAM_JWT_PUBLIC_KEYS_DIR"] = filePath

		_, err := config.LoadFromLookup(lookupFromMap(env))
		if err == nil {
			t.Fatal("expected error when public keys dir is a file, got nil")
		}
		if !strings.Contains(err.Error(), "path is not a directory") {
			t.Errorf("expected not a directory error, got: %v", err)
		}
	})
}

func TestRedactDatabaseURL(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		passwords []string
		expected  string
	}{
		{
			name:      "url with password",
			input:     "postgres://admin:super_secret_password@10.0.0.1:5432/mydb?sslmode=disable",
			passwords: []string{"super_secret_password"},
			expected:  "postgres://admin:REDACTED@10.0.0.1:5432/mydb?sslmode=disable",
		},
		{
			name:      "postgresql url with password",
			input:     "postgresql://app_user:another_secret_pass@localhost:5432/orb",
			passwords: []string{"another_secret_pass"},
			expected:  "postgresql://app_user:REDACTED@localhost:5432/orb",
		},
		{
			name:     "url without password",
			input:    "postgres://localhost:5432/mydb",
			expected: "postgres://localhost:5432/mydb",
		},
		{
			name:     "url with user but no password",
			input:    "postgres://admin@localhost:5432/mydb",
			expected: "postgres://admin@localhost:5432/mydb",
		},
		{
			name:     "empty url",
			input:    "",
			expected: "",
		},
		{
			name:     "whitespace url",
			input:    "   ",
			expected: "",
		},
		{
			name:      "malformed url with postgres scheme",
			input:     "postgres://admin:secret@[::1:invalid/mydb",
			passwords: []string{"secret"},
			expected:  "[redacted-database-url]",
		},
		{
			name:      "url with query password only",
			input:     "postgres://localhost:5432/mydb?password=query_secret_password",
			passwords: []string{"query_secret_password"},
			expected:  "postgres://localhost:5432/mydb?password=REDACTED",
		},
		{
			name:      "postgresql url with query password and other parameters",
			input:     "postgresql://localhost:5432/mydb?sslmode=disable&password=query_secret_password",
			passwords: []string{"query_secret_password"},
			expected:  "postgresql://localhost:5432/mydb?password=REDACTED&sslmode=disable",
		},
		{
			name:      "url with mixed credentials (userinfo password and query password)",
			input:     "postgres://app_user:userinfo_secret@localhost:5432/mydb?password=query_secret&sslmode=disable",
			passwords: []string{"userinfo_secret", "query_secret"},
			expected:  "postgres://app_user:REDACTED@localhost:5432/mydb?password=REDACTED&sslmode=disable",
		},
		{
			name:      "url with mixed credentials and same password",
			input:     "postgres://app_user:shared_secret@localhost:5432/mydb?password=shared_secret",
			passwords: []string{"shared_secret"},
			expected:  "postgres://app_user:REDACTED@localhost:5432/mydb?password=REDACTED",
		},
		{
			name:      "url with uppercase query parameter name",
			input:     "postgres://app_user:userinfo_secret@localhost:5432/mydb?PASSWORD=query_secret",
			passwords: []string{"userinfo_secret", "query_secret"},
			expected:  "postgres://app_user:REDACTED@localhost:5432/mydb?password=REDACTED",
		},
		{
			name:      "url with query sslpassword",
			input:     "postgres://localhost:5432/mydb?sslpassword=cert_secret_pass",
			passwords: []string{"cert_secret_pass"},
			expected:  "postgres://localhost:5432/mydb?sslpassword=REDACTED",
		},
		{
			name:      "url with query password containing encoded characters",
			input:     "postgres://localhost:5432/mydb?password=secret%20with%20spaces",
			passwords: []string{"secret with spaces", "secret%20with%20spaces"},
			expected:  "postgres://localhost:5432/mydb?password=REDACTED",
		},
		{
			name:      "url with malformed query parameters",
			input:     "postgres://localhost:5432/mydb?password=secret%ZZ",
			passwords: []string{"secret"},
			expected:  "[redacted-database-url]",
		},
		{
			name:      "url with query password matching username falls back to placeholder",
			input:     "postgres://secret:user_secret@localhost:5432/mydb?password=secret",
			passwords: []string{"secret", "user_secret"},
			expected:  "[redacted-database-url]",
		},
		{
			name:      "dsn unquoted password",
			input:     "host=localhost port=5432 user=orb password=super_secret_password dbname=orb_control sslmode=disable",
			passwords: []string{"super_secret_password"},
			expected:  "host=localhost port=5432 user=orb password=REDACTED dbname=orb_control sslmode=disable",
		},
		{
			name:      "dsn single quoted password with spaces",
			input:     "host=localhost port=5432 user=orb password='secret with spaces' dbname=orb_control",
			passwords: []string{"secret with spaces"},
			expected:  "host=localhost port=5432 user=orb password=REDACTED dbname=orb_control",
		},
		{
			name:      "dsn single quoted password with escaped quote",
			input:     `host=localhost port=5432 user=orb password='sec\'ret' dbname=orb_control`,
			passwords: []string{"sec'ret"},
			expected:  "host=localhost port=5432 user=orb password=REDACTED dbname=orb_control",
		},
		{
			name:      "dsn double quoted password",
			input:     `host=localhost port=5432 user=orb password="double_secret_pass" dbname=orb_control`,
			passwords: []string{"double_secret_pass"},
			expected:  "host=localhost port=5432 user=orb password=REDACTED dbname=orb_control",
		},
		{
			name:      "dsn spaces around equals",
			input:     "host=localhost port=5432 user=orb password = 'spaced_pass' dbname=orb_control",
			passwords: []string{"spaced_pass"},
			expected:  "host=localhost port=5432 user=orb password = REDACTED dbname=orb_control",
		},
		{
			name:     "dsn without password",
			input:    "host=localhost port=5432 user=orb dbname=orb_control",
			expected: "host=localhost port=5432 user=orb dbname=orb_control",
		},
		{
			name:     "dsn empty password",
			input:    "host=localhost port=5432 user=orb password='' dbname=orb_control",
			expected: "host=localhost port=5432 user=orb password=REDACTED dbname=orb_control",
		},
		{
			name:      "dsn password matches other attribute value",
			input:     "host=localhost user=secret password=secret dbname=orb_control",
			passwords: []string{"secret"},
			expected:  "[redacted-database-dsn]",
		},
		{
			name:     "dsn invalid format",
			input:    "not a valid dsn format = = =",
			expected: "[redacted-database-connstring]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.RedactDatabaseURL(tt.input)
			if got != tt.expected {
				t.Errorf("RedactDatabaseURL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
			for _, p := range tt.passwords {
				if p != "" && strings.Contains(got, p) {
					t.Errorf("Redacted URL leaked password %q: %s", p, got)
				}
			}
		})
	}
}

func TestLoad_HTTPAddressValidation(t *testing.T) {
	validTests := []struct {
		name     string
		addr     string
		wantAddr string
	}{
		{"port only with colon", ":8080", ":8080"},
		{"port only without colon", "8080", ":8080"},
		{"ipv4 with port", "127.0.0.1:8080", "127.0.0.1:8080"},
		{"ipv4 all interfaces", "0.0.0.0:3000", "0.0.0.0:3000"},
		{"localhost with port", "localhost:8080", "localhost:8080"},
		{"bracketed ipv6 with port", "[::1]:8080", "[::1]:8080"},
		{"bracketed ipv6 full with port", "[2001:db8::1]:9090", "[2001:db8::1]:9090"},
	}

	for _, tt := range validTests {
		t.Run("valid_"+tt.name, func(t *testing.T) {
			env := setupValidEnvironment(t)
			env["ORB_IAM_HTTP_ADDR"] = tt.addr

			cfg, err := config.LoadFromLookup(lookupFromMap(env))
			if err != nil {
				t.Fatalf("expected addr %q to be valid, got: %v", tt.addr, err)
			}
			if cfg.HTTPAddr != tt.wantAddr {
				t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, tt.wantAddr)
			}
		})
	}

	invalidTests := []struct {
		name          string
		addr          string
		wantErrSubstr string
	}{
		{"missing port localhost", "localhost", "ORB_IAM_HTTP_ADDR is invalid"},
		{"missing port ipv4", "127.0.0.1", "ORB_IAM_HTTP_ADDR is invalid"},
		{"missing port bracketed ipv6", "[::1]", "ORB_IAM_HTTP_ADDR is invalid"},
		{"unbracketed ipv6", "::1", "ORB_IAM_HTTP_ADDR is invalid"},
		{"extra colons", "127.0.0.1:8080:9090", "ORB_IAM_HTTP_ADDR is invalid"},
		{"non numeric port", "localhost:port", "ORB_IAM_HTTP_ADDR port must be between 1 and 65535"},
		{"port zero", ":0", "ORB_IAM_HTTP_ADDR port must be between 1 and 65535"},
		{"port negative", ":-1", "ORB_IAM_HTTP_ADDR port must be between 1 and 65535"},
		{"port 65536", ":65536", "ORB_IAM_HTTP_ADDR port must be between 1 and 65535"},
		{"port 99999", ":99999", "ORB_IAM_HTTP_ADDR port must be between 1 and 65535"},
	}

	for _, tt := range invalidTests {
		t.Run("invalid_"+tt.name, func(t *testing.T) {
			env := setupValidEnvironment(t)
			env["ORB_IAM_HTTP_ADDR"] = tt.addr

			_, err := config.LoadFromLookup(lookupFromMap(env))
			if err == nil {
				t.Fatalf("expected addr %q to fail, got nil", tt.addr)
			}
			if !strings.Contains(err.Error(), tt.wantErrSubstr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErrSubstr)
			}
		})
	}
}

func TestLoad_DatabaseConnectionFormats(t *testing.T) {
	tests := []struct {
		name  string
		dbURL string
	}{
		{
			name:  "standard postgres url",
			dbURL: "postgres://user:secret@localhost:5432/orb_db?sslmode=disable",
		},
		{
			name:  "postgresql scheme url",
			dbURL: "postgresql://user:secret@localhost:5432/orb_db?sslmode=disable",
		},
		{
			name:  "keyword value DSN",
			dbURL: "host=localhost port=5432 user=orb password=secret dbname=orb_control sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := setupValidEnvironment(t)
			env["ORB_IAM_DATABASE_URL"] = tt.dbURL

			cfg, err := config.LoadFromLookup(lookupFromMap(env))
			if err != nil {
				t.Fatalf("expected valid database connstring to load, got: %v", err)
			}
			if cfg.DatabaseURL != tt.dbURL {
				t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, tt.dbURL)
			}
		})
	}
}

func TestLoad_UsingOsGetenv(t *testing.T) {
	env := setupValidEnvironment(t)
	for k, v := range env {
		t.Setenv(k, v)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("expected Load() with os.Getenv to succeed, got: %v", err)
	}
	if cfg.DatabaseURL != env["ORB_IAM_DATABASE_URL"] {
		t.Errorf("DatabaseURL mismatch")
	}
}
