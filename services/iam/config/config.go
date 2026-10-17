package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	JWTPrivateKeyPath string
	JWTPublicKeysDir  string
	JWTKeyID          string
	JWTIssuer         string
	JWTAudience       string
	JWTTTL            time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		JWTPrivateKeyPath: strings.TrimSpace(
			os.Getenv("ORB_IAM_JWT_PRIVATE_KEY_PATH"),
		),
		JWTPublicKeysDir: strings.TrimSpace(
			os.Getenv("ORB_IAM_JWT_PUBLIC_KEYS_DIR"),
		),
		JWTKeyID: strings.TrimSpace(
			os.Getenv("ORB_IAM_JWT_ACTIVE_KEY_ID"),
		),
		JWTIssuer: strings.TrimSpace(
			os.Getenv("ORB_IAM_JWT_ISSUER"),
		),
		JWTAudience: strings.TrimSpace(
			os.Getenv("ORB_IAM_JWT_AUDIENCE"),
		),
	}

	required := []struct {
		name  string
		value string
	}{
		{"ORB_IAM_JWT_PRIVATE_KEY_PATH", cfg.JWTPrivateKeyPath},
		{"ORB_IAM_JWT_PUBLIC_KEYS_DIR", cfg.JWTPublicKeysDir},
		{"ORB_IAM_JWT_ACTIVE_KEY_ID", cfg.JWTKeyID},
		{"ORB_IAM_JWT_ISSUER", cfg.JWTIssuer},
		{"ORB_IAM_JWT_AUDIENCE", cfg.JWTAudience},
	}

	for _, item := range required {
		if item.value == "" {
			return Config{}, fmt.Errorf("%s is required", item.name)
		}
	}

	ttl := strings.TrimSpace(os.Getenv("ORB_IAM_JWT_TTL"))
	if ttl == "" {
		ttl = "10m"
	}

	parsedTTL, err := time.ParseDuration(ttl)
	if err != nil || parsedTTL <= 0 {
		return Config{}, fmt.Errorf("ORB_IAM_JWT_TTL must be a positive duration")
	}

	cfg.JWTTTL = parsedTTL
	return cfg, nil
}
