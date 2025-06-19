// Example: How to integrate Envoy headers in your Go application
package main

import (
	"fmt"
	"log"
	"net/http"
)

// EnvoyHeaders represents headers that Envoy can add
type EnvoyHeaders struct {
	RequestID     string `header:"x-request-id"`
	SPIFFEID      string `header:"x-spiffe-id"`
	TrustLevel    string `header:"x-trust-level"`
	OriginalIP    string `header:"x-forwarded-for"`
	EnvoyInternal string `header:"x-envoy-internal"`
}

// Middleware to extract Envoy-provided headers
func EnvoyHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Envoy headers
		headers := EnvoyHeaders{
			RequestID:     r.Header.Get("x-request-id"),
			SPIFFEID:      r.Header.Get("x-spiffe-id"),
			TrustLevel:    r.Header.Get("x-trust-level"),
			OriginalIP:    r.Header.Get("x-forwarded-for"),
			EnvoyInternal: r.Header.Get("x-envoy-internal"),
		}

		// Log for debugging
		if headers.RequestID != "" {
			log.Printf("Request ID from Envoy: %s", headers.RequestID)
		}

		if headers.SPIFFEID != "" {
			log.Printf("SPIFFE ID from Envoy: %s", headers.SPIFFEID)
		}

		// Add to request context for use in handlers
		ctx := r.Context()
		// You would typically add headers to context here
		r = r.WithContext(ctx)

		// Set security response headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		next.ServeHTTP(w, r)
	})
}

// Example health check that works with Envoy health checking
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	// Check if request came from Envoy health check
	if r.Header.Get("X-Health-Check") == "envoy" {
		log.Println("Health check from Envoy proxy")
	}

	// Your existing health check logic
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"healthy","timestamp":"%s"}`, "2024-01-01T00:00:00Z")
}

// Example authentication handler that works with Envoy JWT validation
func authHandler(w http.ResponseWriter, r *http.Request) {
	// If Envoy validates JWT, we can trust the request
	spiffeID := r.Header.Get("x-spiffe-id")
	if spiffeID != "" {
		log.Printf("Authenticated request with SPIFFE ID: %s", spiffeID)
		// Trust the authentication done by Envoy
	}

	// Your existing auth logic
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"message":"authenticated"}`)
}

// Example of how to configure your server to work with Envoy
func main() {
	mux := http.NewServeMux()

	// Apply Envoy headers middleware to all routes
	handler := EnvoyHeadersMiddleware(mux)

	// Register routes
	mux.HandleFunc("/health", healthCheckHandler)
	mux.HandleFunc("/api/auth/login", authHandler)

	// Start server on port that Envoy forwards to
	log.Println("Starting server on :8080 (behind Envoy proxy)")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
