package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"mvp.local/pkg/config"
	"mvp.local/pkg/database"
	"mvp.local/pkg/handlers"
	"mvp.local/pkg/models"
	"mvp.local/pkg/observability"
)

func main() {
	// Set simplified auth
	os.Setenv("DISABLE_AUTH", "true")
	
	// Load config
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	
	// Initialize observability
	obsConfig := observability.Config{
		ServiceName:    cfg.Observability.ServiceName,
		ServiceVersion: cfg.Observability.ServiceVersion,
		Environment:    cfg.Observability.Environment,
		LogLevel:       cfg.Observability.LogLevel,
		LogFormat:      cfg.Observability.LogFormat,
	}
	obs, err := observability.New(obsConfig)
	if err != nil {
		log.Fatalf("Failed to init observability: %v", err)
	}
	
	// Initialize database
	db := database.NewDatabase(&cfg.Database)
	err = db.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	
	fmt.Println("✅ Database connected successfully")
	
	// Test direct database queries
	fmt.Println("\n🔍 Testing direct database queries...")
	
	var roles []models.Role
	result := db.GetDB().Find(&roles)
	if result.Error != nil {
		log.Fatalf("❌ Failed to query roles: %v", result.Error)
	}
	fmt.Printf("✅ Found %d roles\n", len(roles))
	
	for _, role := range roles {
		fmt.Printf("  - Role: %+v\n", role)
	}
	
	var users []models.User
	result = db.GetDB().Find(&users)
	if result.Error != nil {
		log.Fatalf("❌ Failed to query users: %v", result.Error)
	}
	fmt.Printf("✅ Found %d users\n", len(users))
	
	for _, user := range users {
		fmt.Printf("  - User: %+v\n", user)
	}
	
	// Test JSON serialization
	fmt.Println("\n🔍 Testing JSON serialization...")
	
	if len(roles) > 0 {
		roleJSON, err := json.Marshal(roles[0])
		if err != nil {
			log.Fatalf("❌ Failed to serialize role: %v", err)
		}
		fmt.Printf("✅ Role JSON: %s\n", string(roleJSON))
	}
	
	if len(users) > 0 {
		userJSON, err := json.Marshal(users[0])
		if err != nil {
			log.Fatalf("❌ Failed to serialize user: %v", err)
		}
		fmt.Printf("✅ User JSON: %s\n", string(userJSON))
	}
	
	// Test admin handler creation
	fmt.Println("\n🔍 Testing admin handler creation...")
	
	adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)
	if adminHandler == nil {
		log.Fatal("❌ Failed to create admin handler")
	}
	fmt.Println("✅ Admin handler created successfully")
	
	// Test hardcoded response
	fmt.Println("\n🔍 Testing hardcoded response...")
	testData := []map[string]interface{}{
		{
			"id":          1,
			"name":        "admin",
			"description": "Administrator role",
			"is_active":   true,
		},
	}
	
	testJSON, err := json.Marshal(testData)
	if err != nil {
		log.Fatalf("❌ Failed to serialize test data: %v", err)
	}
	fmt.Printf("✅ Test data JSON: %s\n", string(testJSON))
	
	fmt.Println("\n✅ All tests passed! The issue is not with basic functionality.")
	fmt.Println("🔍 The problem must be in the Fiber request handling or middleware.")
}