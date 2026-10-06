package main

import (
	"context"
	"log"
	"time"

	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
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

	_ = userService

	log.Println("IAM initialized")
}
