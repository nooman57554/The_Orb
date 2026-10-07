package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
	"github.com/nooman57554/The_Orb/services/iam/handler"
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

	userRepo := repository.NewPostgresUserRepository(db)
	userService := service.NewUserService(userRepo)
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
