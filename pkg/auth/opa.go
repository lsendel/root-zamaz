// Package auth provides Open Policy Agent (OPA) integration for Zero Trust authorization
package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/sdk"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// OPAAuthorizer integrates with Open Policy Agent for Zero Trust authorization
type OPAAuthorizer struct {
	opa    *sdk.OPA
	db     *sql.DB
	config *OPAConfig
}

// OPAConfig holds OPA configuration
type OPAConfig struct {
	ServiceURL    string `json:"serviceUrl"`
	PolicyPath    string `json:"policyPath"`
	DatabaseURL   string `json:"databaseUrl"`
	DecisionLog   bool   `json:"decisionLog"`
	MetricsEnabled bool  `json:"metricsEnabled"`
}

// AuthorizationRequest represents a complete authorization request
type AuthorizationRequest struct {
	// User information from Keycloak
	User UserContext `json:"user"`
	
	// Workload information from SPIRE (optional)
	Workload *WorkloadContext `json:"workload,omitempty"`
	
	// Request details
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Purpose  string `json:"purpose,omitempty"`
	
	// Context information
	Context RequestContext `json:"context"`
	
	// Data information (for data classification policies)
	Data *DataContext `json:"data,omitempty"`
}

// UserContext represents user information for authorization
type UserContext struct {
	UserID              string    `json:"user_id"`
	Email               string    `json:"email"`
	Roles               []string  `json:"roles"`
	TrustLevel          int       `json:"trust_level"`
	DeviceID            string    `json:"device_id,omitempty"`
	DeviceVerified      bool      `json:"device_verified"`
	LastVerification    string    `json:"last_verification,omitempty"`
	SessionFingerprint  string    `json:"session_fingerprint,omitempty"`
	ExpiresAt           int64     `json:"expires_at"`
}

// WorkloadContext represents workload information from SPIRE
type WorkloadContext struct {
	SpiffeID         string `json:"spiffe_id"`
	TrustLevel       int    `json:"trust_level"`
	Attested         bool   `json:"attested"`
	AttestationType  string `json:"attestation_type"`
	HardwareVerified bool   `json:"hardware_verified"`
	CertExpiry       string `json:"cert_expiry"`
	EncryptionEnabled bool  `json:"encryption_enabled"`
	AuditEnabled     bool   `json:"audit_enabled"`
	DLPEnabled       bool   `json:"dlp_enabled"`
	TLSEnabled       bool   `json:"tls_enabled"`
}

// RequestContext represents request context information
type RequestContext struct {
	IPAddress                string            `json:"ip_address,omitempty"`
	UserAgent                string            `json:"user_agent,omitempty"`
	RequestID                string            `json:"request_id,omitempty"`
	SessionID                string            `json:"session_id,omitempty"`
	Country                  string            `json:"country,omitempty"`
	VPNVerified              bool              `json:"vpn_verified"`
	FailedAttempts           int               `json:"failed_attempts"`
	UnusualAccessPattern     bool              `json:"unusual_access_pattern"`
	RateLimitExceeded        bool              `json:"rate_limit_exceeded"`
	SensitiveOperationsCount int               `json:"sensitive_operations_count"`
	Emergency                bool              `json:"emergency"`
	Protocol                 string            `json:"protocol,omitempty"`
	EnvoyProxy               bool              `json:"envoy_proxy"`
	Headers                  map[string]string `json:"headers,omitempty"`
}

// DataContext represents data classification information
type DataContext struct {
	Type           string            `json:"type"`
	Classification string            `json:"classification,omitempty"`
	Fields         []string          `json:"fields,omitempty"`
	Scope          string            `json:"scope,omitempty"`
	CreatedAt      string            `json:"created_at,omitempty"`
	LegalHold      bool              `json:"legal_hold"`
	DeletionScheduled bool           `json:"deletion_scheduled"`
	DeletionDate   string            `json:"deletion_date,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
}

// AuthorizationResponse represents the authorization decision
type AuthorizationResponse struct {
	Allow                 bool                   `json:"allow"`
	Reasons               []string               `json:"reasons,omitempty"`
	TrustLevel            int                    `json:"trust_level"`
	RequiredTrustLevel    int                    `json:"required_trust_level"`
	AuditRequired         bool                   `json:"audit_required"`
	AdditionalChecks      map[string]bool        `json:"additional_checks,omitempty"`
	DecisionID            string                 `json:"decision_id"`
	EvaluationTimeMS      int64                  `json:"evaluation_time_ms"`
	PolicyVersion         string                 `json:"policy_version,omitempty"`
	DataClassification    string                 `json:"data_classification,omitempty"`
	ComplianceFlags       []string               `json:"compliance_flags,omitempty"`
}

// NewOPAAuthorizer creates a new OPA authorizer
func NewOPAAuthorizer(ctx context.Context, config *OPAConfig) (*OPAAuthorizer, error) {
	if config == nil {
		return nil, fmt.Errorf("OPA config cannot be nil")
	}

	// Set defaults
	if config.PolicyPath == "" {
		config.PolicyPath = "/zero_trust/authz"
	}

	// Create OPA SDK instance
	opaConfig := fmt.Sprintf(`{
		"services": {
			"authz": {
				"url": "%s"
			}
		},
		"bundles": {
			"authz": {
				"resource": "/v1/data/zero_trust"
			}
		}
	}`, config.ServiceURL)

	opa, err := sdk.New(ctx, sdk.Options{
		ID:     "zero-trust-authz",
		Config: opaConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA SDK: %w", err)
	}

	// Connect to PostgreSQL for decision logging if configured
	var db *sql.DB
	if config.DatabaseURL != "" {
		db, err = sql.Open("postgres", config.DatabaseURL)
		if err != nil {
			opa.Stop(ctx)
			return nil, fmt.Errorf("unable to connect to database: %w", err)
		}

		// Test connection
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			opa.Stop(ctx)
			return nil, fmt.Errorf("unable to ping database: %w", err)
		}
	}

	return &OPAAuthorizer{
		opa:    opa,
		db:     db,
		config: config,
	}, nil
}

// Authorize makes an authorization decision using OPA policies
func (o *OPAAuthorizer) Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error) {
	startTime := time.Now()
	decisionID := uuid.New().String()

	// Make decision using OPA
	result, err := o.opa.Decision(ctx, sdk.DecisionOptions{
		Path:  o.config.PolicyPath,
		Input: req,
	})
	if err != nil {
		return nil, fmt.Errorf("OPA decision failed: %w", err)
	}

	evaluationTime := time.Since(startTime).Milliseconds()

	// Parse OPA result
	response := &AuthorizationResponse{
		DecisionID:       decisionID,
		EvaluationTimeMS: evaluationTime,
	}

	// Extract decision result
	if resultMap, ok := result.Result.(map[string]interface{}); ok {
		// Parse authorization decision
		if authDecision, exists := resultMap["authorization_decision"]; exists {
			if authMap, ok := authDecision.(map[string]interface{}); ok {
				if allow, ok := authMap["allow"].(bool); ok {
					response.Allow = allow
				}
				if reasons, ok := authMap["reasons"].([]interface{}); ok {
					for _, reason := range reasons {
						if reasonStr, ok := reason.(string); ok {
							response.Reasons = append(response.Reasons, reasonStr)
						}
					}
				}
				if trustLevel, ok := authMap["trust_level"].(float64); ok {
					response.TrustLevel = int(trustLevel)
				}
				if requiredTrust, ok := authMap["required_trust_level"].(float64); ok {
					response.RequiredTrustLevel = int(requiredTrust)
				}
				if audit, ok := authMap["audit_required"].(bool); ok {
					response.AuditRequired = audit
				}
				if checks, ok := authMap["additional_checks"].(map[string]interface{}); ok {
					response.AdditionalChecks = make(map[string]bool)
					for key, value := range checks {
						if boolVal, ok := value.(bool); ok {
							response.AdditionalChecks[key] = boolVal
						}
					}
				}
			}
		} else {
			// Fallback: check simple allow decision
			if allow, ok := resultMap["allow"].(bool); ok {
				response.Allow = allow
			}
		}

		// Extract data classification if present
		if dataDecision, exists := resultMap["data_access_decision"]; exists {
			if dataMap, ok := dataDecision.(map[string]interface{}); ok {
				if classification, ok := dataMap["data_classification"].(string); ok {
					response.DataClassification = classification
				}
			}
		}
	}

	// Log decision if configured
	if o.config.DecisionLog && o.db != nil {
		go o.logDecision(context.Background(), req, response, result)
	}

	// Update metrics if configured
	if o.config.MetricsEnabled && o.db != nil {
		go o.updateMetrics(context.Background(), o.config.PolicyPath, evaluationTime, response.Allow)
	}

	return response, nil
}

// AuthorizeWorkload authorizes service-to-service communication
func (o *OPAAuthorizer) AuthorizeWorkload(ctx context.Context, sourceSpiffeID, targetSpiffeID string, context RequestContext) (*AuthorizationResponse, error) {
	req := &AuthorizationRequest{
		Workload: &WorkloadContext{
			SpiffeID: sourceSpiffeID,
			Attested: true,
		},
		Resource: "workload_communication",
		Action:   "connect",
		Context:  context,
		Data: &DataContext{
			Type: "service_communication",
			Attributes: map[string]string{
				"source_spiffe_id": sourceSpiffeID,
				"target_spiffe_id": targetSpiffeID,
			},
		},
	}

	// Use workload-specific policy path
	originalPath := o.config.PolicyPath
	o.config.PolicyPath = "/zero_trust/workload"
	defer func() { o.config.PolicyPath = originalPath }()

	return o.Authorize(ctx, req)
}

// AuthorizeDataAccess authorizes data access with classification checks
func (o *OPAAuthorizer) AuthorizeDataAccess(ctx context.Context, user UserContext, dataType, purpose string, fields []string) (*AuthorizationResponse, error) {
	req := &AuthorizationRequest{
		User:     user,
		Resource: "data_access",
		Action:   "read",
		Purpose:  purpose,
		Context: RequestContext{
			RequestID: uuid.New().String(),
		},
		Data: &DataContext{
			Type:   dataType,
			Fields: fields,
			Scope:  "single_record",
		},
	}

	// Use data-specific policy path
	originalPath := o.config.PolicyPath
	o.config.PolicyPath = "/zero_trust/data"
	defer func() { o.config.PolicyPath = originalPath }()

	return o.Authorize(ctx, req)
}

// logDecision logs the authorization decision to the database
func (o *OPAAuthorizer) logDecision(ctx context.Context, req *AuthorizationRequest, resp *AuthorizationResponse, result *sdk.DecisionResult) {
	if o.db == nil {
		return
	}

	// Serialize input and result data
	inputData, _ := json.Marshal(req)
	resultData, _ := json.Marshal(result.Result)

	// Extract compliance flags
	var complianceFlags []string
	if req.Purpose != "" {
		complianceFlags = append(complianceFlags, "purpose_specified")
	}
	if resp.AuditRequired {
		complianceFlags = append(complianceFlags, "audit_required")
	}

	// Insert decision log
	query := `
		INSERT INTO decision_logs (
			decision_id, user_id, user_email, user_roles, user_trust_level,
			workload_spiffe_id, workload_trust_level, workload_attested,
			resource, action, purpose, decision, denial_reasons, trust_level_required,
			ip_address, user_agent, request_id, session_id,
			evaluation_time_ms, input_data, result_data,
			audit_required, compliance_flags, data_classification
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24
		)`

	var workloadSpiffeID *string
	var workloadTrustLevel *int
	var workloadAttested *bool
	if req.Workload != nil {
		workloadSpiffeID = &req.Workload.SpiffeID
		workloadTrustLevel = &req.Workload.TrustLevel
		workloadAttested = &req.Workload.Attested
	}

	var ipAddress *string
	var userAgent *string
	var requestID *string
	var sessionID *string
	if req.Context.IPAddress != "" {
		ipAddress = &req.Context.IPAddress
	}
	if req.Context.UserAgent != "" {
		userAgent = &req.Context.UserAgent
	}
	if req.Context.RequestID != "" {
		requestID = &req.Context.RequestID
	}
	if req.Context.SessionID != "" {
		sessionID = &req.Context.SessionID
	}

	_, err := o.db.ExecContext(ctx, query,
		resp.DecisionID,
		req.User.UserID,
		req.User.Email,
		req.User.Roles,
		req.User.TrustLevel,
		workloadSpiffeID,
		workloadTrustLevel,
		workloadAttested,
		req.Resource,
		req.Action,
		req.Purpose,
		resp.Allow,
		resp.Reasons,
		resp.RequiredTrustLevel,
		ipAddress,
		userAgent,
		requestID,
		sessionID,
		resp.EvaluationTimeMS,
		inputData,
		resultData,
		resp.AuditRequired,
		complianceFlags,
		resp.DataClassification,
	)

	if err != nil {
		log.Printf("Failed to log OPA decision: %v", err)
	}
}

// updateMetrics updates policy evaluation metrics
func (o *OPAAuthorizer) updateMetrics(ctx context.Context, policyPath string, evaluationTime int64, success bool) {
	if o.db == nil {
		return
	}

	query := `
		INSERT INTO policy_metrics (policy_name, evaluation_count, total_evaluation_time_ms, success_count, failure_count)
		VALUES ($1, 1, $2, $3, $4)
		ON CONFLICT (policy_name, rule_name) 
		DO UPDATE SET
			evaluation_count = policy_metrics.evaluation_count + 1,
			total_evaluation_time_ms = policy_metrics.total_evaluation_time_ms + EXCLUDED.total_evaluation_time_ms,
			success_count = policy_metrics.success_count + EXCLUDED.success_count,
			failure_count = policy_metrics.failure_count + EXCLUDED.failure_count,
			last_evaluation = NOW(),
			updated_at = NOW()`

	successCount := 0
	failureCount := 0
	if success {
		successCount = 1
	} else {
		failureCount = 1
	}

	_, err := o.db.ExecContext(ctx, query, policyPath, evaluationTime, successCount, failureCount)
	if err != nil {
		log.Printf("Failed to update OPA metrics: %v", err)
	}
}

// GetDecisionLogs retrieves decision logs for analysis
func (o *OPAAuthorizer) GetDecisionLogs(ctx context.Context, filters DecisionLogFilters) ([]DecisionLog, error) {
	if o.db == nil {
		return nil, fmt.Errorf("database not configured")
	}

	query := `
		SELECT decision_id, timestamp, user_id, user_email, resource, action, 
		       decision, denial_reasons, trust_level_required, user_trust_level,
		       audit_required, ip_address, evaluation_time_ms
		FROM decision_logs 
		WHERE timestamp >= $1 AND timestamp <= $2`
	
	args := []interface{}{filters.StartTime, filters.EndTime}
	argCount := 2

	if filters.UserID != "" {
		argCount++
		query += fmt.Sprintf(" AND user_id = $%d", argCount)
		args = append(args, filters.UserID)
	}

	if filters.Resource != "" {
		argCount++
		query += fmt.Sprintf(" AND resource = $%d", argCount)
		args = append(args, filters.Resource)
	}

	if filters.DecisionOnly != nil {
		argCount++
		query += fmt.Sprintf(" AND decision = $%d", argCount)
		args = append(args, *filters.DecisionOnly)
	}

	query += " ORDER BY timestamp DESC LIMIT $" + fmt.Sprintf("%d", argCount+1)
	args = append(args, filters.Limit)

	rows, err := o.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query decision logs: %w", err)
	}
	defer rows.Close()

	var logs []DecisionLog
	for rows.Next() {
		var log DecisionLog
		var ipAddress *string
		
		err := rows.Scan(
			&log.DecisionID,
			&log.Timestamp,
			&log.UserID,
			&log.UserEmail,
			&log.Resource,
			&log.Action,
			&log.Decision,
			&log.DenialReasons,
			&log.TrustLevelRequired,
			&log.UserTrustLevel,
			&log.AuditRequired,
			&ipAddress,
			&log.EvaluationTimeMS,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan decision log: %w", err)
		}

		if ipAddress != nil {
			log.IPAddress = *ipAddress
		}

		logs = append(logs, log)
	}

	return logs, rows.Err()
}

// GetPolicyMetrics retrieves policy evaluation metrics
func (o *OPAAuthorizer) GetPolicyMetrics(ctx context.Context) ([]PolicyMetric, error) {
	if o.db == nil {
		return nil, fmt.Errorf("database not configured")
	}

	query := `
		SELECT policy_name, rule_name, evaluation_count, total_evaluation_time_ms,
		       success_count, failure_count, last_evaluation
		FROM policy_metrics
		ORDER BY evaluation_count DESC`

	rows, err := o.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query policy metrics: %w", err)
	}
	defer rows.Close()

	var metrics []PolicyMetric
	for rows.Next() {
		var metric PolicyMetric
		var ruleName *string

		err := rows.Scan(
			&metric.PolicyName,
			&ruleName,
			&metric.EvaluationCount,
			&metric.TotalEvaluationTimeMS,
			&metric.SuccessCount,
			&metric.FailureCount,
			&metric.LastEvaluation,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy metric: %w", err)
		}

		if ruleName != nil {
			metric.RuleName = *ruleName
		}

		if metric.EvaluationCount > 0 {
			metric.AverageEvaluationTimeMS = float64(metric.TotalEvaluationTimeMS) / float64(metric.EvaluationCount)
		}

		metrics = append(metrics, metric)
	}

	return metrics, rows.Err()
}

// HealthCheck verifies OPA connectivity and service status
func (o *OPAAuthorizer) HealthCheck(ctx context.Context) error {
	// Simple health check with a test decision
	testReq := &AuthorizationRequest{
		User: UserContext{
			UserID:     "health-check",
			Email:      "test@example.com",
			Roles:      []string{"user"},
			TrustLevel: 25,
		},
		Resource: "health",
		Action:   "check",
		Context: RequestContext{
			RequestID: "health-check",
		},
	}

	_, err := o.Authorize(ctx, testReq)
	return err
}

// Close cleans up the OPA authorizer
func (o *OPAAuthorizer) Close() error {
	var errors []string

	if o.opa != nil {
		o.opa.Stop(context.Background())
	}

	if o.db != nil {
		if err := o.db.Close(); err != nil {
			errors = append(errors, fmt.Sprintf("database close error: %v", err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("close errors: %s", fmt.Sprintf("%v", errors))
	}

	return nil
}

// Supporting types for decision logging and metrics

type DecisionLogFilters struct {
	StartTime     time.Time
	EndTime       time.Time
	UserID        string
	Resource      string
	DecisionOnly  *bool
	Limit         int
}

type DecisionLog struct {
	DecisionID          string    `json:"decision_id"`
	Timestamp           time.Time `json:"timestamp"`
	UserID              string    `json:"user_id"`
	UserEmail           string    `json:"user_email"`
	Resource            string    `json:"resource"`
	Action              string    `json:"action"`
	Decision            bool      `json:"decision"`
	DenialReasons       []string  `json:"denial_reasons"`
	TrustLevelRequired  int       `json:"trust_level_required"`
	UserTrustLevel      int       `json:"user_trust_level"`
	AuditRequired       bool      `json:"audit_required"`
	IPAddress           string    `json:"ip_address"`
	EvaluationTimeMS    int64     `json:"evaluation_time_ms"`
}

type PolicyMetric struct {
	PolicyName              string    `json:"policy_name"`
	RuleName                string    `json:"rule_name"`
	EvaluationCount         int       `json:"evaluation_count"`
	TotalEvaluationTimeMS   int64     `json:"total_evaluation_time_ms"`
	AverageEvaluationTimeMS float64   `json:"average_evaluation_time_ms"`
	SuccessCount            int       `json:"success_count"`
	FailureCount            int       `json:"failure_count"`
	LastEvaluation          time.Time `json:"last_evaluation"`
}