package main

import (
	"fmt"
	"log"
	"net/http/httptest"
	"os"

	"github.com/gofiber/fiber/v2"
	"mvp.local/pkg/config"
	"mvp.local/pkg/database"
	"mvp.local/pkg/handlers"
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
		LogLevel:       "error", // Reduce noise
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
	
	fmt.Println("✅ Setup completed")
	
	// Test 1: Minimal Fiber app with just hardcoded response
	fmt.Println("\n🔍 Test 1: Minimal hardcoded endpoint...")
	
	app1 := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			fmt.Printf("❌ Fiber Error: %v\n", err)
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		},
	})
	
	app1.Get("/test", func(c *fiber.Ctx) error {
		return c.JSON(map[string]interface{}{
			"message": "success",
			"data":    []string{"test1", "test2"},
		})
	})
	
	req1 := httptest.NewRequest("GET", "/test", nil)
	resp1, err := app1.Test(req1, 1000)
	if err != nil {
		fmt.Printf("❌ Test 1 failed: %v\n", err)
	} else {
		fmt.Printf("✅ Test 1 passed: Status %d\n", resp1.StatusCode)
	}
	
	// Test 2: Admin handler with no middleware
	fmt.Println("\n🔍 Test 2: Admin handler without middleware...")
	
	adminHandler := handlers.NewAdminHandler(db.GetDB(), nil, obs)
	
	app2 := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			fmt.Printf("❌ Fiber Error: %v\n", err)
			return c.Status(500).JSON(fiber.Map{"error": err.Error()})
		},
	})
	
	app2.Get("/admin/roles", adminHandler.GetRoles)
	
	req2 := httptest.NewRequest("GET", "/admin/roles", nil)
	resp2, err := app2.Test(req2, 1000)
	if err != nil {
		fmt.Printf("❌ Test 2 failed: %v\n", err)
	} else {
		fmt.Printf("✅ Test 2 result: Status %d\n", resp2.StatusCode)
		
		// Try to read response
		body := make([]byte, 1024)
		n, _ := resp2.Body.Read(body)
		fmt.Printf("Response: %s\n", string(body[:n]))
	}
	
	// Test 3: Check if the issue is in middleware
	fmt.Println("\n🔍 Test 3: Testing with auth middleware...")
	
	// Note: We can't easily test this without recreating the full server setup,
	// but the above tests should isolate whether the issue is in the handler itself
	// or in the middleware stack.
	
	fmt.Println("\n🔍 Analysis complete!")
}