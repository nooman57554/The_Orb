package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
	"github.com/nooman57554/The_Orb/services/iam/auth"
	"github.com/nooman57554/The_Orb/services/iam/config"
	"github.com/nooman57554/The_Orb/services/iam/handler"
	"github.com/nooman57554/The_Orb/services/iam/keyloader"
	"github.com/nooman57554/The_Orb/services/iam/repository"
	"github.com/nooman57554/The_Orb/services/iam/service"
)

func main() {
	ctx := context.Background()

	dbConfig := dbconnector.Config{
		DatabaseURL:     "postgres://orb:orb@localhost:5432/orb_control?sslmode=disable",
		MaxConns:        10,
		MinConns:        2,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
		HealthCheckTime: 1 * time.Minute,
	}

	db, err := dbconnector.New(ctx, dbConfig)
	if err != nil {
		log.Fatalf("create database connector: %v", err)
	}
	defer db.Close()

	jwtManager, err := getJWTManager()
	if err != nil {
		log.Fatalf("get JWT manager: %v", err)
	}

	userRepo := repository.NewPostgresUserRepository(db)
	userService := service.NewUserService(userRepo)
	authService := service.NewAuthService(userRepo)
	userHandler := handler.NewUserHandler(userService)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/users", userHandler.CreateUser)
	mux.HandleFunc("GET /v1/users/{id}", userHandler.GetUser)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Println("IAM server listening on :8080")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("IAM server failed: %v", err)
	}

	log.Println("IAM initialized")
}

func getJWTManager() (*auth.JWTManager, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load IAM configuration: %w", err)
	}

	keyLoader, err := keyloader.NewFileLoader(
		cfg.JWTPrivateKeyPath,
		cfg.JWTPublicKeysDir,
		cfg.JWTKeyID,
	)
	if err != nil {
		return nil, fmt.Errorf("configure JWT key loader: %w", err)
	}

	keySet, err := keyLoader.Load(context.Background())
	if err != nil {
		return nil, fmt.Errorf("load JWT keys: %w", err)
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
		return nil, fmt.Errorf("initialize JWT manager: %w", err)
	}

	return jwtManager, nil
}
