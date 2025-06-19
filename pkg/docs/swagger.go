// Package docs provides API documentation utilities and enhanced Swagger configuration.
package docs

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/swagger"
)

// SwaggerConfig holds Swagger UI configuration
type SwaggerConfig struct {
	Title         string
	Description   string
	Version       string
	BasePath      string
	Host          string
	DocsURL       string
	DeepLinking   bool
	DocExpansion  string
	DefaultModels bool
}

// DefaultSwaggerConfig returns default Swagger configuration
func DefaultSwaggerConfig() SwaggerConfig {
	return SwaggerConfig{
		Title:         "Zero Trust Authentication API",
		Description:   "Comprehensive API for Zero Trust Authentication MVP system with device attestation, RBAC, and observability",
		Version:       "1.0.0",
		BasePath:      "/api",
		Host:          "localhost:8080",
		DocsURL:       "/swagger/doc.json",
		DeepLinking:   true,
		DocExpansion:  "list",
		DefaultModels: true,
	}
}

// SetupSwagger configures Swagger documentation routes
func SetupSwagger(app *fiber.App, config ...SwaggerConfig) {
	cfg := DefaultSwaggerConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	// Configure Swagger middleware
	swaggerConfig := swagger.Config{
		URL:                      cfg.DocsURL,
		DeepLinking:              cfg.DeepLinking,
		DocExpansion:             cfg.DocExpansion,
		DefaultModelsExpandDepth: -1,
		Title:                    cfg.Title,
	}

	if cfg.DefaultModels {
		swaggerConfig.DefaultModelsExpandDepth = 1
	}

	// Add Swagger routes
	app.Get("/swagger/*", swagger.New(swaggerConfig))

	// Alternative documentation endpoints
	app.Get("/docs/*", swagger.New(swaggerConfig))
	app.Get("/api-docs/*", swagger.New(swaggerConfig))
}

// APIInfo provides structured API information
type APIInfo struct {
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Version     string           `json:"version"`
	Contact     ContactInfo      `json:"contact"`
	License     LicenseInfo      `json:"license"`
	Servers     []ServerInfo     `json:"servers"`
	Tags        []TagInfo        `json:"tags"`
	Security    []SecurityScheme `json:"security"`
}

// ContactInfo provides API contact information
type ContactInfo struct {
	Name  string `json:"name"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// LicenseInfo provides API license information
type LicenseInfo struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// ServerInfo provides server information
type ServerInfo struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

// TagInfo provides endpoint tag information
type TagInfo struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	ExternalDocs string `json:"externalDocs,omitempty"`
}

// SecurityScheme provides security scheme information
type SecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	Description  string `json:"description,omitempty"`
}

// GetAPIInfo returns comprehensive API information
func GetAPIInfo() APIInfo {
	return APIInfo{
		Title:       "Zero Trust Authentication API",
		Description: "A comprehensive Zero Trust Authentication system providing secure device attestation, role-based access control, and comprehensive observability features.",
		Version:     "1.0.0",
		Contact: ContactInfo{
			Name:  "API Support",
			Email: "support@zerotrust.local",
		},
		License: LicenseInfo{
			Name: "Apache 2.0",
			URL:  "http://www.apache.org/licenses/LICENSE-2.0.html",
		},
		Servers: []ServerInfo{
			{
				URL:         "http://localhost:8080",
				Description: "Development server",
			},
			{
				URL:         "https://staging.zerotrust.local",
				Description: "Staging server",
			},
			{
				URL:         "https://api.zerotrust.local",
				Description: "Production server",
			},
		},
		Tags: []TagInfo{
			{
				Name:        "Authentication",
				Description: "User authentication and session management",
			},
			{
				Name:        "Devices",
				Description: "Device attestation and management",
			},
			{
				Name:        "Administration",
				Description: "Administrative operations for users, roles, and permissions",
			},
			{
				Name:        "System",
				Description: "System health, metrics, and monitoring",
			},
			{
				Name:        "Security",
				Description: "Security-related operations and monitoring",
			},
		},
		Security: []SecurityScheme{
			{
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
				Description:  "JWT token authentication. Use 'Bearer {token}' format.",
			},
		},
	}
}

// CommonResponses provides common HTTP response definitions
func CommonResponses() map[string]interface{} {
	return map[string]interface{}{
		"400": map[string]interface{}{
			"description": "Bad Request - Invalid input parameters",
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type":        "object",
								"description": "Error details",
								"properties": map[string]interface{}{
									"type":    map[string]interface{}{"type": "string", "example": "validation"},
									"code":    map[string]interface{}{"type": "string", "example": "VALIDATION_FAILED"},
									"message": map[string]interface{}{"type": "string", "example": "Invalid input parameters"},
									"fields":  map[string]interface{}{"type": "object", "description": "Field-specific errors"},
								},
							},
							"success":   map[string]interface{}{"type": "boolean", "example": false},
							"timestamp": map[string]interface{}{"type": "string", "format": "date-time"},
						},
					},
				},
			},
		},
		"401": map[string]interface{}{
			"description": "Unauthorized - Authentication required",
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"type":    map[string]interface{}{"type": "string", "example": "authentication"},
									"code":    map[string]interface{}{"type": "string", "example": "INVALID_CREDENTIALS"},
									"message": map[string]interface{}{"type": "string", "example": "Authentication required"},
								},
							},
							"success": map[string]interface{}{"type": "boolean", "example": false},
						},
					},
				},
			},
		},
		"403": map[string]interface{}{
			"description": "Forbidden - Insufficient permissions",
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"type":    map[string]interface{}{"type": "string", "example": "authorization"},
									"code":    map[string]interface{}{"type": "string", "example": "INSUFFICIENT_PERMISSIONS"},
									"message": map[string]interface{}{"type": "string", "example": "Insufficient permissions"},
								},
							},
							"success": map[string]interface{}{"type": "boolean", "example": false},
						},
					},
				},
			},
		},
		"404": map[string]interface{}{
			"description": "Not Found - Resource not found",
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"type":    map[string]interface{}{"type": "string", "example": "not_found"},
									"code":    map[string]interface{}{"type": "string", "example": "RESOURCE_NOT_FOUND"},
									"message": map[string]interface{}{"type": "string", "example": "Resource not found"},
								},
							},
							"success": map[string]interface{}{"type": "boolean", "example": false},
						},
					},
				},
			},
		},
		"429": map[string]interface{}{
			"description": "Too Many Requests - Rate limit exceeded",
			"headers": map[string]interface{}{
				"Retry-After": map[string]interface{}{
					"description": "Number of seconds to wait before retrying",
					"schema":      map[string]interface{}{"type": "integer"},
				},
				"X-RateLimit-Limit": map[string]interface{}{
					"description": "Request limit per time window",
					"schema":      map[string]interface{}{"type": "integer"},
				},
				"X-RateLimit-Remaining": map[string]interface{}{
					"description": "Remaining requests in current window",
					"schema":      map[string]interface{}{"type": "integer"},
				},
			},
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"type":    map[string]interface{}{"type": "string", "example": "rate_limit"},
									"code":    map[string]interface{}{"type": "string", "example": "RATE_LIMIT_EXCEEDED"},
									"message": map[string]interface{}{"type": "string", "example": "Rate limit exceeded"},
								},
							},
							"success": map[string]interface{}{"type": "boolean", "example": false},
						},
					},
				},
			},
		},
		"500": map[string]interface{}{
			"description": "Internal Server Error",
			"content": map[string]interface{}{
				"application/json": map[string]interface{}{
					"schema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"error": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"type":    map[string]interface{}{"type": "string", "example": "internal"},
									"code":    map[string]interface{}{"type": "string", "example": "INTERNAL_ERROR"},
									"message": map[string]interface{}{"type": "string", "example": "An internal error occurred"},
								},
							},
							"success": map[string]interface{}{"type": "boolean", "example": false},
						},
					},
				},
			},
		},
	}
}

// SecurityRequirements provides common security requirements
func SecurityRequirements() map[string]interface{} {
	return map[string]interface{}{
		"BearerAuth": []string{},
	}
}
