-- Initialize OPA Database for Decision Logging and Policy Management
-- Part of Framework Integration Plan - Week 3

-- Create dedicated database for OPA
CREATE DATABASE opa_decisions;

-- Create dedicated user for OPA
CREATE USER opa WITH ENCRYPTED PASSWORD 'opa123';

-- Grant all privileges on the OPA database to the OPA user
GRANT ALL PRIVILEGES ON DATABASE opa_decisions TO opa;

-- Connect to the opa_decisions database and set up permissions
\connect opa_decisions;

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO opa;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO opa;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO opa;

-- Enable UUID extension for better ID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create decision log table
CREATE TABLE IF NOT EXISTS decision_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    decision_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Request information
    user_id VARCHAR(255),
    user_email VARCHAR(255),
    user_roles TEXT[],
    user_trust_level INTEGER,
    
    -- Workload information  
    workload_spiffe_id VARCHAR(2048),
    workload_trust_level INTEGER,
    workload_attested BOOLEAN,
    
    -- Request details
    resource VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    purpose VARCHAR(255),
    
    -- Decision result
    decision BOOLEAN NOT NULL,
    denial_reasons TEXT[],
    trust_level_required INTEGER,
    
    -- Context information
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    session_id VARCHAR(255),
    
    -- Policy information
    policy_version VARCHAR(50),
    evaluation_time_ms INTEGER,
    
    -- Full decision payload (for detailed analysis)
    input_data JSONB,
    result_data JSONB,
    
    -- Audit and compliance
    audit_required BOOLEAN DEFAULT FALSE,
    compliance_flags TEXT[],
    data_classification VARCHAR(50),
    
    -- Indexing hints
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create policy evaluation metrics table
CREATE TABLE IF NOT EXISTS policy_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_name VARCHAR(255) NOT NULL,
    rule_name VARCHAR(255),
    evaluation_count INTEGER DEFAULT 1,
    total_evaluation_time_ms INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    last_evaluation TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(policy_name, rule_name)
);

-- Create trust level analytics table
CREATE TABLE IF NOT EXISTS trust_level_analytics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    date DATE DEFAULT CURRENT_DATE,
    hour INTEGER DEFAULT EXTRACT(HOUR FROM NOW()),
    
    -- Trust level distribution
    trust_level_none_count INTEGER DEFAULT 0,
    trust_level_low_count INTEGER DEFAULT 0,
    trust_level_medium_count INTEGER DEFAULT 0,
    trust_level_high_count INTEGER DEFAULT 0,
    trust_level_full_count INTEGER DEFAULT 0,
    
    -- Decision outcomes by trust level
    decisions_allowed INTEGER DEFAULT 0,
    decisions_denied INTEGER DEFAULT 0,
    
    -- Resource access patterns
    resource_type VARCHAR(255),
    action_type VARCHAR(255),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(date, hour, resource_type, action_type)
);

-- Create security incident table
CREATE TABLE IF NOT EXISTS security_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_type VARCHAR(255) NOT NULL,
    severity VARCHAR(50) NOT NULL, -- low, medium, high, critical
    
    -- Associated user/workload
    user_id VARCHAR(255),
    workload_spiffe_id VARCHAR(2048),
    
    -- Incident details
    description TEXT NOT NULL,
    indicators JSONB,
    decision_ids UUID[], -- Associated decision log entries
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    first_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_observed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,
    
    -- Resolution
    status VARCHAR(50) DEFAULT 'open', -- open, investigating, resolved, false_positive
    assigned_to VARCHAR(255),
    resolution_notes TEXT,
    resolved_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create policy compliance audit table
CREATE TABLE IF NOT EXISTS compliance_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_date DATE DEFAULT CURRENT_DATE,
    
    -- Compliance framework
    framework VARCHAR(100) NOT NULL, -- GDPR, SOX, HIPAA, etc.
    requirement VARCHAR(255) NOT NULL,
    
    -- Compliance status
    status VARCHAR(50) NOT NULL, -- compliant, non_compliant, needs_review
    score DECIMAL(5,2), -- Compliance score (0-100)
    
    -- Evidence and details
    evidence JSONB,
    violations TEXT[],
    recommendations TEXT[],
    
    -- Associated data
    decision_count INTEGER DEFAULT 0,
    violation_count INTEGER DEFAULT 0,
    
    -- Auditor information
    audited_by VARCHAR(255),
    audit_notes TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create performance optimization hints table
CREATE TABLE IF NOT EXISTS policy_performance (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- Policy identification
    policy_path VARCHAR(500) NOT NULL,
    rule_name VARCHAR(255),
    
    -- Performance metrics
    avg_evaluation_time_ms DECIMAL(10,3),
    max_evaluation_time_ms INTEGER,
    min_evaluation_time_ms INTEGER,
    evaluation_count INTEGER,
    
    -- Optimization suggestions
    complexity_score INTEGER, -- 1-10 scale
    optimization_suggestions TEXT[],
    cache_hit_ratio DECIMAL(5,4),
    
    -- Time period
    measurement_start TIMESTAMP WITH TIME ZONE,
    measurement_end TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_decision_logs_timestamp ON decision_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_decision_logs_user_id ON decision_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_decision_logs_workload_spiffe_id ON decision_logs(workload_spiffe_id);
CREATE INDEX IF NOT EXISTS idx_decision_logs_resource ON decision_logs(resource);
CREATE INDEX IF NOT EXISTS idx_decision_logs_action ON decision_logs(action);
CREATE INDEX IF NOT EXISTS idx_decision_logs_decision ON decision_logs(decision);
CREATE INDEX IF NOT EXISTS idx_decision_logs_audit_required ON decision_logs(audit_required);
CREATE INDEX IF NOT EXISTS idx_decision_logs_ip_address ON decision_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_decision_logs_created_at ON decision_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_policy_metrics_policy_name ON policy_metrics(policy_name);
CREATE INDEX IF NOT EXISTS idx_policy_metrics_last_evaluation ON policy_metrics(last_evaluation);

CREATE INDEX IF NOT EXISTS idx_trust_analytics_date_hour ON trust_level_analytics(date, hour);
CREATE INDEX IF NOT EXISTS idx_trust_analytics_resource_action ON trust_level_analytics(resource_type, action_type);

CREATE INDEX IF NOT EXISTS idx_security_incidents_type ON security_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_security_incidents_severity ON security_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_security_incidents_status ON security_incidents(status);
CREATE INDEX IF NOT EXISTS idx_security_incidents_user_id ON security_incidents(user_id);
CREATE INDEX IF NOT EXISTS idx_security_incidents_first_observed ON security_incidents(first_observed);

CREATE INDEX IF NOT EXISTS idx_compliance_audit_date ON compliance_audit(audit_date);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_framework ON compliance_audit(framework);
CREATE INDEX IF NOT EXISTS idx_compliance_audit_status ON compliance_audit(status);

-- Create functions for automated analysis

-- Function to aggregate trust level statistics
CREATE OR REPLACE FUNCTION update_trust_level_analytics(
    analysis_date DATE DEFAULT CURRENT_DATE,
    analysis_hour INTEGER DEFAULT EXTRACT(HOUR FROM NOW())
) RETURNS VOID AS $$
BEGIN
    INSERT INTO trust_level_analytics (
        date, hour, 
        trust_level_none_count, trust_level_low_count, trust_level_medium_count,
        trust_level_high_count, trust_level_full_count,
        decisions_allowed, decisions_denied
    )
    SELECT 
        analysis_date,
        analysis_hour,
        COUNT(*) FILTER (WHERE user_trust_level < 25) as none_count,
        COUNT(*) FILTER (WHERE user_trust_level >= 25 AND user_trust_level < 50) as low_count,
        COUNT(*) FILTER (WHERE user_trust_level >= 50 AND user_trust_level < 75) as medium_count,
        COUNT(*) FILTER (WHERE user_trust_level >= 75 AND user_trust_level < 100) as high_count,
        COUNT(*) FILTER (WHERE user_trust_level >= 100) as full_count,
        COUNT(*) FILTER (WHERE decision = true) as allowed_count,
        COUNT(*) FILTER (WHERE decision = false) as denied_count
    FROM decision_logs
    WHERE DATE(timestamp) = analysis_date 
    AND EXTRACT(HOUR FROM timestamp) = analysis_hour
    ON CONFLICT (date, hour, resource_type, action_type) 
    DO UPDATE SET
        trust_level_none_count = EXCLUDED.trust_level_none_count,
        trust_level_low_count = EXCLUDED.trust_level_low_count,
        trust_level_medium_count = EXCLUDED.trust_level_medium_count,
        trust_level_high_count = EXCLUDED.trust_level_high_count,
        trust_level_full_count = EXCLUDED.trust_level_full_count,
        decisions_allowed = EXCLUDED.decisions_allowed,
        decisions_denied = EXCLUDED.decisions_denied;
END;
$$ LANGUAGE plpgsql;

-- Function to detect security incidents
CREATE OR REPLACE FUNCTION detect_security_incidents() RETURNS INTEGER AS $$
DECLARE
    incident_count INTEGER := 0;
    suspicious_user RECORD;
    incident_id UUID;
BEGIN
    -- Detect multiple failed access attempts
    FOR suspicious_user IN
        SELECT user_id, ip_address, COUNT(*) as failure_count
        FROM decision_logs
        WHERE decision = false 
        AND timestamp > NOW() - INTERVAL '1 hour'
        AND user_id IS NOT NULL
        GROUP BY user_id, ip_address
        HAVING COUNT(*) >= 5
    LOOP
        -- Check if incident already exists
        SELECT id INTO incident_id
        FROM security_incidents
        WHERE incident_type = 'multiple_failed_attempts'
        AND user_id = suspicious_user.user_id
        AND ip_address = suspicious_user.ip_address
        AND status = 'open'
        AND first_observed > NOW() - INTERVAL '24 hours';
        
        IF incident_id IS NULL THEN
            -- Create new incident
            INSERT INTO security_incidents (
                incident_type, severity, user_id, ip_address, description,
                indicators, occurrence_count
            ) VALUES (
                'multiple_failed_attempts',
                CASE 
                    WHEN suspicious_user.failure_count >= 20 THEN 'critical'
                    WHEN suspicious_user.failure_count >= 10 THEN 'high'
                    ELSE 'medium'
                END,
                suspicious_user.user_id,
                suspicious_user.ip_address,
                format('User %s from IP %s had %s failed access attempts in the last hour',
                    suspicious_user.user_id, suspicious_user.ip_address, suspicious_user.failure_count),
                jsonb_build_object(
                    'failure_count', suspicious_user.failure_count,
                    'time_window', '1 hour',
                    'detection_rule', 'multiple_failed_attempts'
                ),
                suspicious_user.failure_count
            );
            incident_count := incident_count + 1;
        ELSE
            -- Update existing incident
            UPDATE security_incidents 
            SET occurrence_count = suspicious_user.failure_count,
                last_observed = NOW(),
                updated_at = NOW(),
                indicators = jsonb_set(
                    indicators, 
                    '{failure_count}', 
                    to_jsonb(suspicious_user.failure_count)
                )
            WHERE id = incident_id;
        END IF;
    END LOOP;
    
    RETURN incident_count;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate compliance scores
CREATE OR REPLACE FUNCTION calculate_compliance_score(
    framework_name VARCHAR(100),
    audit_date DATE DEFAULT CURRENT_DATE
) RETURNS DECIMAL(5,2) AS $$
DECLARE
    total_decisions INTEGER;
    compliant_decisions INTEGER;
    compliance_score DECIMAL(5,2);
BEGIN
    -- Count total decisions for the day
    SELECT COUNT(*) INTO total_decisions
    FROM decision_logs
    WHERE DATE(timestamp) = audit_date;
    
    IF total_decisions = 0 THEN
        RETURN 100.00; -- Perfect score if no decisions made
    END IF;
    
    -- Framework-specific compliance checks
    CASE framework_name
        WHEN 'GDPR' THEN
            -- GDPR compliance: purpose limitation, data minimization, audit trails
            SELECT COUNT(*) INTO compliant_decisions
            FROM decision_logs
            WHERE DATE(timestamp) = audit_date
            AND purpose IS NOT NULL
            AND audit_required = true;
            
        WHEN 'SOX' THEN
            -- SOX compliance: financial data access controls
            SELECT COUNT(*) INTO compliant_decisions
            FROM decision_logs
            WHERE DATE(timestamp) = audit_date
            AND (resource != 'financial' OR audit_required = true);
            
        WHEN 'HIPAA' THEN
            -- HIPAA compliance: healthcare data protection
            SELECT COUNT(*) INTO compliant_decisions
            FROM decision_logs
            WHERE DATE(timestamp) = audit_date
            AND (data_classification != 'personal_health_information' OR user_trust_level >= 75);
            
        ELSE
            -- Default: require audit for sensitive operations
            SELECT COUNT(*) INTO compliant_decisions
            FROM decision_logs
            WHERE DATE(timestamp) = audit_date
            AND (resource NOT IN ('admin', 'financial') OR audit_required = true);
    END CASE;
    
    compliance_score := (compliant_decisions::DECIMAL / total_decisions::DECIMAL) * 100.0;
    
    -- Insert compliance audit record
    INSERT INTO compliance_audit (
        audit_date, framework, requirement, status, score,
        decision_count, evidence
    ) VALUES (
        audit_date,
        framework_name,
        'automated_daily_check',
        CASE 
            WHEN compliance_score >= 95.0 THEN 'compliant'
            WHEN compliance_score >= 80.0 THEN 'needs_review'
            ELSE 'non_compliant'
        END,
        compliance_score,
        total_decisions,
        jsonb_build_object(
            'total_decisions', total_decisions,
            'compliant_decisions', compliant_decisions,
            'calculation_method', 'automated'
        )
    ) ON CONFLICT (audit_date, framework, requirement) 
    DO UPDATE SET
        score = EXCLUDED.score,
        status = EXCLUDED.status,
        decision_count = EXCLUDED.decision_count,
        evidence = EXCLUDED.evidence;
    
    RETURN compliance_score;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions on all objects to opa user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO opa;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO opa;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO opa;

-- Insert some sample policy metrics
INSERT INTO policy_metrics (policy_name, rule_name, evaluation_count, total_evaluation_time_ms, success_count) VALUES
('zero_trust.authz', 'allow', 0, 0, 0),
('zero_trust.authz', 'user_authenticated', 0, 0, 0),
('zero_trust.authz', 'sufficient_trust_level', 0, 0, 0),
('zero_trust.workload', 'allow', 0, 0, 0),
('zero_trust.data', 'allow', 0, 0, 0);

-- Create views for common queries

-- Trust level distribution view
CREATE VIEW trust_level_distribution AS
SELECT 
    DATE(timestamp) as date,
    CASE 
        WHEN user_trust_level >= 100 THEN 'FULL'
        WHEN user_trust_level >= 75 THEN 'HIGH'
        WHEN user_trust_level >= 50 THEN 'MEDIUM'
        WHEN user_trust_level >= 25 THEN 'LOW'
        ELSE 'NONE'
    END as trust_level,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE decision = true) as allowed_count,
    COUNT(*) FILTER (WHERE decision = false) as denied_count
FROM decision_logs
WHERE timestamp > NOW() - INTERVAL '30 days'
GROUP BY DATE(timestamp), 
    CASE 
        WHEN user_trust_level >= 100 THEN 'FULL'
        WHEN user_trust_level >= 75 THEN 'HIGH'
        WHEN user_trust_level >= 50 THEN 'MEDIUM'
        WHEN user_trust_level >= 25 THEN 'LOW'
        ELSE 'NONE'
    END;

-- Resource access patterns view
CREATE VIEW resource_access_patterns AS
SELECT 
    resource,
    action,
    COUNT(*) as total_requests,
    COUNT(*) FILTER (WHERE decision = true) as allowed_requests,
    COUNT(*) FILTER (WHERE decision = false) as denied_requests,
    ROUND(
        (COUNT(*) FILTER (WHERE decision = true)::DECIMAL / COUNT(*)::DECIMAL) * 100, 2
    ) as approval_rate,
    AVG(user_trust_level) as avg_trust_level
FROM decision_logs
WHERE timestamp > NOW() - INTERVAL '7 days'
GROUP BY resource, action
ORDER BY total_requests DESC;