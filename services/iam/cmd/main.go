package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
	"github.com/nooman57554/The_Orb/orb_libs/identity/httpauth"
	"github.com/nooman57554/The_Orb/orb_libs/identity/jwtverify"
	"github.com/nooman57554/The_Orb/services/iam/auth"
	"github.com/nooman57554/The_Orb/services/iam/config"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/keyloader"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

func main() {
	ctx := context.Background()

	// load config
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load IAM configuration: %v", err)
	}

	dbConfig := dbconnector.Config{
		DatabaseURL:     "postgres://orb:orb@localhost:5432/orb_control?sslmode=disable",
		MaxConns:        10,
		MinConns:        2,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
		HealthCheckTime: 1 * time.Minute,
	}

	// create DB connection pool
	db, err := dbconnector.New(ctx, dbConfig)
	if err != nil {
		log.Fatalf("create database connector: %v", err)
	}
	defer db.Close()

	// initialize JWT manager and verifier
	jwtManager, tokenVerifier, err := initAuth(cfg)
	if err != nil {
		log.Fatalf("initialize JWT auth: %v", err)
	}

	// create repositories
	userRepo := repository.NewPostgresUserRepository(db)
	sessionRepo := repository.NewPostgresSessionRepository(db)

	// create services
	userService := service.NewUserService(userRepo)
	authService, err := service.NewAuthService(
		userRepo,
		sessionRepo,
		jwtManager,
		cfg.JWTTTL,
		cfg.RefreshTokenTTL,
	)
	if err != nil {
		log.Fatalf("initialize auth service: %v", err)
	}

	// create handlers
	userHandler := handler.NewUserHandler(userService)
	authHandler := handler.NewAuthHandler(authService)

	// create bearer middleware with default-protected routing and explicit public exemptions
	bearerMiddleware, err := httpauth.NewBearerMiddleware(
		tokenVerifier,
		sessionRepo,
		"POST /v1/auth/login",
		"POST /v1/auth/refresh",
		"POST /v1/auth/logout",
		"POST /v1/users",
	)
	if err != nil {
		log.Fatalf("initialize bearer middleware: %v", err)
	}

	// Create router
	mux := http.NewServeMux()

	// User routes
	mux.HandleFunc("POST /v1/users", userHandler.CreateUser)
	mux.HandleFunc("GET /v1/users/{id}", userHandler.GetUser)

	// Auth routes
	mux.HandleFunc("POST /v1/auth/login", authHandler.Login)
	mux.HandleFunc("POST /v1/auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /v1/auth/logout", authHandler.Logout)

	server := &http.Server{
		Addr:    ":8080",
		Handler: bearerMiddleware.Require(mux),
	}

	log.Println("IAM server listening on :8080")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("IAM server failed: %v", err)
	}

	log.Println("IAM initialized")
}

func initAuth(cfg config.Config) (*auth.JWTManager, *jwtverify.Verifier, error) {
	keyLoader, err := keyloader.NewFileLoader(
		cfg.JWTPrivateKeyPath,
		cfg.JWTPublicKeysDir,
		cfg.JWTKeyID,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("configure JWT key loader: %w", err)
	}

	keySet, err := keyLoader.Load(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("load JWT keys: %w", err)
	}

	jwtManager, err := auth.NewJWTManager(
		keySet.PrivateKey,
		keySet.ActiveKeyID,
		keySet.PublicKeys,
		cfg.JWTIssuer,
		cfg.JWTAudience,
		cfg.JWTTTL,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize JWT manager: %w", err)
	}

	tokenVerifier, err := jwtverify.NewVerifier(
		keySet.PublicKeys,
		cfg.JWTIssuer,
		cfg.JWTAudience,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize token verifier: %w", err)
	}

	return jwtManager, tokenVerifier, nil
}
