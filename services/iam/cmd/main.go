package main

import (
	"context"
	"log"

	"github.com/nooman57554/The_Orb/orb_libs/dbconnector"
)

func main() {
	ctx := context.Background()

	databaseURL := "postgres://platform:platform@localhost:5432/platform"

	db, err := dbconnector.New(ctx, databaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	defer db.Close()

	log.Println("IAM service started")
	log.Println("database connection successful")
}
