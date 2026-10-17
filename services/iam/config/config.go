package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	JWTKeyID          string
	JWTIssuer         string
	JWTAudience       string
	JWTTTL            time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		JWTPrivateKeyPath: os.Getenv("ORB_IAM_JWT_PRIVATE_KEY_PATH"),
		JWTPublicKeyPath:  os.Getenv("ORB_IAM_JWT_PUBLIC_KEY_PATH"),
		JWTKeyID:          os.Getenv("ORB_IAM_JWT_KEY_ID"),
		JWTIssuer:         os.Getenv("ORB_IAM_JWT_ISSUER"),
		JWTAudience:       os.Getenv("ORB_IAM_JWT_AUDIENCE"),
	}

	for name, value := range map[string]string{
		"ORB_IAM_JWT_PRIVATE_KEY_PATH": cfg.JWTPrivateKeyPath,
		"ORB_IAM_JWT_PUBLIC_KEY_PATH":  cfg.JWTPublicKeyPath,
		"ORB_IAM_JWT_KEY_ID":           cfg.JWTKeyID,
		"ORB_IAM_JWT_ISSUER":           cfg.JWTIssuer,
		"ORB_IAM_JWT_AUDIENCE":         cfg.JWTAudience,
	} {
		if value == "" {
			return Config{}, fmt.Errorf("%s is required", name)
		}
	}

	ttl := os.Getenv("ORB_IAM_JWT_TTL")
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
