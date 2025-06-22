// Package auth provides SPIRE/SPIFFE workload identity integration for Zero Trust
package auth

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// SPIREAuthenticator integrates with SPIRE for workload identity and attestation
type SPIREAuthenticator struct {
	source   *workloadapi.X509Source
	jwtSource *workloadapi.JWTSource
	db       *sql.DB
	config   *SPIREConfig
}

// SPIREConfig holds SPIRE configuration
type SPIREConfig struct {
	SocketPath     string `json:"socketPath"`
	TrustDomain    string `json:"trustDomain"`
	DatabaseURL    string `json:"databaseUrl"`
	DefaultTTL     time.Duration `json:"defaultTtl"`
	MetricsEnabled bool   `json:"metricsEnabled"`
}

// WorkloadIdentity represents a workload's SPIFFE identity
type WorkloadIdentity struct {
	SpiffeID         string                 `json:"spiffeId"`
	TrustLevel       int                    `json:"trustLevel"`
	AttestationType  string                 `json:"attestationType"`
	HardwareVerified bool                   `json:"hardwareVerified"`
	LastAttestation  time.Time              `json:"lastAttestation"`
	DeviceID         string                 `json:"deviceId,omitempty"`
	Certificates     []*x509.Certificate    `json:"-"` // Sensitive data not serialized
	JWTToken         string                 `json:"-"` // Sensitive data not serialized
	Claims           map[string]interface{} `json:"claims,omitempty"`
	ExpiresAt        time.Time              `json:"expiresAt"`
}

// AttestationData represents attestation evidence
type AttestationData struct {
	AttestorType    string                 `json:"attestorType"`
	Evidence        map[string]interface{} `json:"evidence"`
	Timestamp       time.Time              `json:"timestamp"`
	NodeID          string                 `json:"nodeId,omitempty"`
	WorkloadPath    string                 `json:"workloadPath,omitempty"`
	ContainerID     string                 `json:"containerId,omitempty"`
	KubernetesAttrs map[string]string      `json:"kubernetesAttrs,omitempty"`
}

// TrustLevelUpdate represents a trust level change request
type TrustLevelUpdate struct {
	SpiffeID        string           `json:"spiffeId"`
	NewTrustLevel   int              `json:"newTrustLevel"`
	Reason          string           `json:"reason"`
	AttestationData *AttestationData `json:"attestationData,omitempty"`
	ChangedBy       string           `json:"changedBy"`
}

// NewSPIREAuthenticator creates a new SPIRE authenticator
func NewSPIREAuthenticator(ctx context.Context, config *SPIREConfig) (*SPIREAuthenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("SPIRE config cannot be nil")
	}

	// Set defaults
	if config.SocketPath == "" {
		config.SocketPath = "unix:///opt/spire/sockets/agent.sock"
	}
	if config.TrustDomain == "" {
		config.TrustDomain = "zero-trust.dev"
	}
	if config.DefaultTTL == 0 {
		config.DefaultTTL = time.Hour
	}

	// Create X.509 source for certificate-based identity
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(
		workloadapi.WithAddr(config.SocketPath),
	))
	if err != nil {
		return nil, fmt.Errorf("unable to create X509Source: %w", err)
	}

	// Create JWT source for JWT-SVID tokens
	jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(
		workloadapi.WithAddr(config.SocketPath),
	))
	if err != nil {
		source.Close()
		return nil, fmt.Errorf("unable to create JWTSource: %w", err)
	}

	// Connect to PostgreSQL for trust level management
	var db *sql.DB
	if config.DatabaseURL != "" {
		db, err = sql.Open("postgres", config.DatabaseURL)
		if err != nil {
			source.Close()
			jwtSource.Close()
			return nil, fmt.Errorf("unable to connect to database: %w", err)
		}

		// Test connection
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			source.Close()
			jwtSource.Close()
			return nil, fmt.Errorf("unable to ping database: %w", err)
		}
	}

	return &SPIREAuthenticator{
		source:    source,
		jwtSource: jwtSource,
		db:        db,
		config:    config,
	}, nil
}

// GetWorkloadIdentity retrieves the current workload's identity
func (s *SPIREAuthenticator) GetWorkloadIdentity(ctx context.Context) (*WorkloadIdentity, error) {
	// Get X.509 SVID
	svid, err := s.source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("unable to get X509 SVID: %w", err)
	}

	// Calculate trust level based on SPIFFE ID and attestation
	trustLevel, err := s.calculateTrustFromSVID(ctx, svid)
	if err != nil {
		log.Printf("Warning: failed to calculate trust level: %v", err)
		trustLevel = 25 // Default to LOW trust
	}

	// Get attestation data
	attestationType, hardwareVerified := s.extractAttestationInfo(svid)

	identity := &WorkloadIdentity{
		SpiffeID:         svid.ID.String(),
		TrustLevel:       trustLevel,
		AttestationType:  attestationType,
		HardwareVerified: hardwareVerified,
		LastAttestation:  time.Now(),
		Certificates:     svid.Certificates,
		ExpiresAt:        svid.Certificates[0].NotAfter,
	}

	return identity, nil
}

// GetJWTToken retrieves a JWT-SVID token for the workload
func (s *SPIREAuthenticator) GetJWTToken(ctx context.Context, audience string) (*WorkloadIdentity, error) {
	// Fetch JWT-SVID
	jwtSVID, err := s.jwtSource.FetchJWTSVID(ctx, workloadapi.JWTSVIDParams{
		Audience: audience,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to fetch JWT SVID: %w", err)
	}

	// Parse claims
	claims := make(map[string]interface{})
	if len(jwtSVID.Claims) > 0 {
		for key, value := range jwtSVID.Claims {
			claims[key] = value
		}
	}

	// Calculate trust level
	trustLevel, err := s.calculateTrustFromSpiffeID(ctx, jwtSVID.ID.String())
	if err != nil {
		log.Printf("Warning: failed to calculate trust level: %v", err)
		trustLevel = 25
	}

	identity := &WorkloadIdentity{
		SpiffeID:        jwtSVID.ID.String(),
		TrustLevel:      trustLevel,
		JWTToken:        jwtSVID.Marshal(),
		Claims:          claims,
		LastAttestation: time.Now(),
		ExpiresAt:       jwtSVID.Expiry,
	}

	return identity, nil
}

// ValidateJWTToken validates a JWT-SVID token
func (s *SPIREAuthenticator) ValidateJWTToken(ctx context.Context, token, audience string) (*WorkloadIdentity, error) {
	// Get trust bundles for validation
	bundles, err := s.source.GetJWTBundles()
	if err != nil {
		return nil, fmt.Errorf("unable to get JWT bundles: %w", err)
	}

	// Parse and validate JWT
	jwtSVID, err := workloadapi.ParseAndValidateJWTSVID(token, bundles, audience)
	if err != nil {
		return nil, fmt.Errorf("JWT validation failed: %w", err)
	}

	// Extract claims
	claims := make(map[string]interface{})
	for key, value := range jwtSVID.Claims {
		claims[key] = value
	}

	// Calculate trust level
	trustLevel, err := s.calculateTrustFromSpiffeID(ctx, jwtSVID.ID.String())
	if err != nil {
		trustLevel = 25
	}

	return &WorkloadIdentity{
		SpiffeID:        jwtSVID.ID.String(),
		TrustLevel:      trustLevel,
		Claims:          claims,
		LastAttestation: time.Now(),
		ExpiresAt:       jwtSVID.Expiry,
	}, nil
}

// calculateTrustFromSVID calculates trust level from X.509 SVID
func (s *SPIREAuthenticator) calculateTrustFromSVID(ctx context.Context, svid *workloadapi.X509SVID) (int, error) {
	return s.calculateTrustFromSpiffeID(ctx, svid.ID.String())
}

// calculateTrustFromSpiffeID calculates trust level from SPIFFE ID
func (s *SPIREAuthenticator) calculateTrustFromSpiffeID(ctx context.Context, spiffeIDStr string) (int, error) {
	// Parse SPIFFE ID
	spiffeID, err := spiffeid.FromString(spiffeIDStr)
	if err != nil {
		return 25, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	// If database is available, get trust level from DB
	if s.db != nil {
		var trustLevel int
		err := s.db.QueryRowContext(ctx, 
			"SELECT get_effective_trust_level($1)", spiffeIDStr).Scan(&trustLevel)
		if err == nil {
			return trustLevel, nil
		}
		log.Printf("Warning: failed to get trust level from DB: %v", err)
	}

	// Fallback to path-based trust calculation
	path := spiffeID.Path()
	
	switch {
	case strings.HasPrefix(path, "/admin"):
		return 100, nil // FULL trust for admin workloads
	case strings.HasPrefix(path, "/api"):
		return 75, nil  // HIGH trust for API workloads
	case strings.HasPrefix(path, "/worker"):
		return 50, nil  // MEDIUM trust for worker processes
	case strings.HasPrefix(path, "/public"):
		return 25, nil  // LOW trust for public services
	default:
		return 25, nil  // Default to LOW trust
	}
}

// extractAttestationInfo extracts attestation information from SVID
func (s *SPIREAuthenticator) extractAttestationInfo(svid *workloadapi.X509SVID) (string, bool) {
	// Default values
	attestationType := "unknown"
	hardwareVerified := false

	// Examine certificate extensions and subject for attestation hints
	cert := svid.Certificates[0]
	
	// Look for custom extensions that might indicate attestation type
	for _, ext := range cert.Extensions {
		// This is a simplified approach - in practice, you'd define
		// custom OIDs for different attestation types
		if len(ext.Value) > 0 {
			// Basic pattern matching based on extension values
			extStr := string(ext.Value)
			if strings.Contains(extStr, "k8s") {
				attestationType = "k8s_sat"
			} else if strings.Contains(extStr, "tpm") {
				attestationType = "tpm"
				hardwareVerified = true
			} else if strings.Contains(extStr, "aws") {
				attestationType = "aws_iid"
			}
		}
	}

	// Examine subject for additional hints
	subject := cert.Subject.String()
	if strings.Contains(subject, "kubernetes") {
		attestationType = "k8s_sat"
	}

	return attestationType, hardwareVerified
}

// UpdateWorkloadTrustLevel updates the trust level for a workload
func (s *SPIREAuthenticator) UpdateWorkloadTrustLevel(ctx context.Context, update *TrustLevelUpdate) error {
	if s.db == nil {
		return fmt.Errorf("database not configured")
	}

	// Validate SPIFFE ID
	_, err := spiffeid.FromString(update.SpiffeID)
	if err != nil {
		return fmt.Errorf("invalid SPIFFE ID: %w", err)
	}

	// Serialize attestation data
	var attestationDataJSON []byte
	if update.AttestationData != nil {
		attestationDataJSON, err = json.Marshal(update.AttestationData)
		if err != nil {
			return fmt.Errorf("failed to serialize attestation data: %w", err)
		}
	}

	// Call the database function to update trust level with audit
	var success bool
	err = s.db.QueryRowContext(ctx, `
		SELECT update_workload_trust_level($1, $2, $3, $4, $5)`,
		update.SpiffeID,
		update.NewTrustLevel,
		update.Reason,
		update.ChangedBy,
		attestationDataJSON,
	).Scan(&success)

	if err != nil {
		return fmt.Errorf("failed to update trust level: %w", err)
	}

	if !success {
		return fmt.Errorf("trust level update failed - workload not found")
	}

	return nil
}

// GetWorkloadTrustLevel retrieves the current trust level for a workload
func (s *SPIREAuthenticator) GetWorkloadTrustLevel(ctx context.Context, spiffeID string) (int, error) {
	if s.db == nil {
		// Fallback to path-based calculation
		return s.calculateTrustFromSpiffeID(ctx, spiffeID)
	}

	var trustLevel int
	err := s.db.QueryRowContext(ctx, 
		"SELECT get_effective_trust_level($1)", spiffeID).Scan(&trustLevel)
	if err != nil {
		if err == sql.ErrNoRows {
			// Fallback to path-based calculation
			return s.calculateTrustFromSpiffeID(ctx, spiffeID)
		}
		return 0, fmt.Errorf("failed to get trust level: %w", err)
	}

	return trustLevel, nil
}

// ListWorkloadIdentities lists all known workload identities
func (s *SPIREAuthenticator) ListWorkloadIdentities(ctx context.Context) ([]*WorkloadIdentity, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT spiffe_id, trust_level, attestation_type, last_attestation, 
		       device_id, hardware_verified
		FROM workload_trust_levels 
		ORDER BY last_attestation DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query workload identities: %w", err)
	}
	defer rows.Close()

	var identities []*WorkloadIdentity
	for rows.Next() {
		identity := &WorkloadIdentity{}
		err := rows.Scan(
			&identity.SpiffeID,
			&identity.TrustLevel,
			&identity.AttestationType,
			&identity.LastAttestation,
			&identity.DeviceID,
			&identity.HardwareVerified,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}
		identities = append(identities, identity)
	}

	return identities, rows.Err()
}

// GetTrustAuditLog retrieves trust level change audit log
func (s *SPIREAuthenticator) GetTrustAuditLog(ctx context.Context, spiffeID string, limit int) ([]map[string]interface{}, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not configured")
	}

	query := `
		SELECT spiffe_id, old_trust_level, new_trust_level, reason,
		       attestation_data, changed_by, changed_at, ip_address
		FROM workload_trust_audit 
		WHERE spiffe_id = $1 
		ORDER BY changed_at DESC 
		LIMIT $2`

	rows, err := s.db.QueryContext(ctx, query, spiffeID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit log: %w", err)
	}
	defer rows.Close()

	var auditLog []map[string]interface{}
	for rows.Next() {
		var (
			spiffeID, reason, changedBy          string
			oldTrust, newTrust                   *int
			changedAt                            time.Time
			attestationData                      *string
			ipAddress                            *string
		)

		err := rows.Scan(&spiffeID, &oldTrust, &newTrust, &reason,
			&attestationData, &changedBy, &changedAt, &ipAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit row: %w", err)
		}

		entry := map[string]interface{}{
			"spiffe_id":      spiffeID,
			"old_trust_level": oldTrust,
			"new_trust_level": newTrust,
			"reason":         reason,
			"changed_by":     changedBy,
			"changed_at":     changedAt.Format(time.RFC3339),
		}

		if attestationData != nil {
			entry["attestation_data"] = *attestationData
		}
		if ipAddress != nil {
			entry["ip_address"] = *ipAddress
		}

		auditLog = append(auditLog, entry)
	}

	return auditLog, rows.Err()
}

// HealthCheck verifies SPIRE connectivity and service status
func (s *SPIREAuthenticator) HealthCheck(ctx context.Context) error {
	// Test X.509 source
	_, err := s.source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("X.509 source health check failed: %w", err)
	}

	// Test JWT source
	_, err = s.jwtSource.GetJWTBundles()
	if err != nil {
		return fmt.Errorf("JWT source health check failed: %w", err)
	}

	// Test database connection if configured
	if s.db != nil {
		err = s.db.PingContext(ctx)
		if err != nil {
			return fmt.Errorf("database health check failed: %w", err)
		}
	}

	return nil
}

// GetStats returns SPIRE integration statistics
func (s *SPIREAuthenticator) GetStats(ctx context.Context) (map[string]interface{}, error) {
	stats := map[string]interface{}{
		"trust_domain":     s.config.TrustDomain,
		"socket_path":      s.config.SocketPath,
		"database_enabled": s.db != nil,
	}

	// Get current workload identity info
	identity, err := s.GetWorkloadIdentity(ctx)
	if err == nil {
		stats["current_spiffe_id"] = identity.SpiffeID
		stats["current_trust_level"] = identity.TrustLevel
		stats["current_attestation_type"] = identity.AttestationType
		stats["current_hardware_verified"] = identity.HardwareVerified
		stats["cert_expires_at"] = identity.ExpiresAt.Format(time.RFC3339)
	}

	// Get workload count from database
	if s.db != nil {
		var workloadCount int
		err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM workload_trust_levels").Scan(&workloadCount)
		if err == nil {
			stats["total_workloads"] = workloadCount
		}

		// Get trust level distribution
		rows, err := s.db.QueryContext(ctx, `
			SELECT trust_level, COUNT(*) 
			FROM workload_trust_levels 
			GROUP BY trust_level 
			ORDER BY trust_level`)
		if err == nil {
			trustDistribution := make(map[string]int)
			for rows.Next() {
				var trustLevel, count int
				rows.Scan(&trustLevel, &count)
				
				var levelName string
				switch {
				case trustLevel >= 100:
					levelName = "FULL"
				case trustLevel >= 75:
					levelName = "HIGH"
				case trustLevel >= 50:
					levelName = "MEDIUM"
				case trustLevel >= 25:
					levelName = "LOW"
				default:
					levelName = "NONE"
				}
				trustDistribution[levelName] = count
			}
			rows.Close()
			stats["trust_level_distribution"] = trustDistribution
		}
	}

	return stats, nil
}

// Close cleans up the SPIRE authenticator
func (s *SPIREAuthenticator) Close() error {
	var errors []string

	if s.source != nil {
		if err := s.source.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("X.509 source close error: %v", err))
		}
	}

	if s.jwtSource != nil {
		if err := s.jwtSource.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("JWT source close error: %v", err))
		}
	}

	if s.db != nil {
		if err := s.db.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("database close error: %v", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("close errors: %s", strings.Join(errors, "; "))
	}

	return nil
}