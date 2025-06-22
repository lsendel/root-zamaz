-- Initialize SPIRE Database
-- Part of Framework Integration Plan - Week 2

-- Create dedicated database for SPIRE
CREATE DATABASE spire;

-- Create dedicated user for SPIRE
CREATE USER spire WITH ENCRYPTED PASSWORD 'spire123';

-- Grant all privileges on the SPIRE database to the SPIRE user
GRANT ALL PRIVILEGES ON DATABASE spire TO spire;

-- Connect to the spire database and set up permissions
\connect spire;

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO spire;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO spire;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO spire;

-- Enable UUID extension for better ID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create custom tables for Zero Trust integration
CREATE TABLE IF NOT EXISTS workload_trust_levels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    spiffe_id VARCHAR(2048) NOT NULL UNIQUE,
    trust_level INTEGER NOT NULL DEFAULT 25,
    attestation_type VARCHAR(255) NOT NULL,
    last_attestation TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    device_id VARCHAR(255),
    hardware_verified BOOLEAN DEFAULT FALSE,
    policy_enforced BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create trust level audit table
CREATE TABLE IF NOT EXISTS workload_trust_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    spiffe_id VARCHAR(2048) NOT NULL,
    old_trust_level INTEGER,
    new_trust_level INTEGER NOT NULL,
    reason TEXT NOT NULL,
    attestation_data JSONB,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT
);

-- Create attestation policy table
CREATE TABLE IF NOT EXISTS attestation_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_name VARCHAR(255) NOT NULL UNIQUE,
    spiffe_id_pattern VARCHAR(2048) NOT NULL,
    required_trust_level INTEGER NOT NULL DEFAULT 25,
    required_attestors TEXT[], -- Array of required attestor types
    policy_data JSONB,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create workload registration requests table
CREATE TABLE IF NOT EXISTS workload_registrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    spiffe_id VARCHAR(2048) NOT NULL,
    parent_id VARCHAR(2048),
    selectors TEXT[] NOT NULL,
    trust_level INTEGER NOT NULL DEFAULT 25,
    dns_names TEXT[],
    ttl INTEGER DEFAULT 3600,
    status VARCHAR(50) DEFAULT 'pending',
    requested_by VARCHAR(255),
    approved_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    approved_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_workload_trust_spiffe_id ON workload_trust_levels(spiffe_id);
CREATE INDEX IF NOT EXISTS idx_workload_trust_level ON workload_trust_levels(trust_level);
CREATE INDEX IF NOT EXISTS idx_workload_trust_attestation_type ON workload_trust_levels(attestation_type);
CREATE INDEX IF NOT EXISTS idx_workload_trust_last_attestation ON workload_trust_levels(last_attestation);

CREATE INDEX IF NOT EXISTS idx_trust_audit_spiffe_id ON workload_trust_audit(spiffe_id);
CREATE INDEX IF NOT EXISTS idx_trust_audit_changed_at ON workload_trust_audit(changed_at);

CREATE INDEX IF NOT EXISTS idx_attestation_policies_pattern ON attestation_policies(spiffe_id_pattern);
CREATE INDEX IF NOT EXISTS idx_attestation_policies_active ON attestation_policies(active);

CREATE INDEX IF NOT EXISTS idx_workload_reg_spiffe_id ON workload_registrations(spiffe_id);
CREATE INDEX IF NOT EXISTS idx_workload_reg_status ON workload_registrations(status);
CREATE INDEX IF NOT EXISTS idx_workload_reg_created_at ON workload_registrations(created_at);

-- Insert default attestation policies
INSERT INTO attestation_policies (policy_name, spiffe_id_pattern, required_trust_level, required_attestors, policy_data) VALUES
('admin_workloads', 'spiffe://zero-trust.dev/admin/*', 100, ARRAY['k8s_sat', 'tpm'], '{"require_hardware_attestation": true, "require_mfa": true}'),
('api_services', 'spiffe://zero-trust.dev/api/*', 75, ARRAY['k8s_sat'], '{"require_verified_deployment": true}'),
('worker_services', 'spiffe://zero-trust.dev/worker/*', 50, ARRAY['k8s_sat', 'docker'], '{"require_container_verification": true}'),
('public_services', 'spiffe://zero-trust.dev/public/*', 25, ARRAY['k8s_sat'], '{"basic_verification": true}');

-- Insert default workload trust levels
INSERT INTO workload_trust_levels (spiffe_id, trust_level, attestation_type, hardware_verified) VALUES
('spiffe://zero-trust.dev/admin/controller', 100, 'k8s_sat', true),
('spiffe://zero-trust.dev/api/auth-service', 75, 'k8s_sat', false),
('spiffe://zero-trust.dev/api/user-service', 75, 'k8s_sat', false),
('spiffe://zero-trust.dev/worker/job-processor', 50, 'docker', false),
('spiffe://zero-trust.dev/public/health-check', 25, 'k8s_sat', false);

-- Create function to update trust level with audit
CREATE OR REPLACE FUNCTION update_workload_trust_level(
    target_spiffe_id VARCHAR(2048),
    new_trust_level INTEGER,
    reason TEXT,
    changed_by VARCHAR(255) DEFAULT 'system',
    attestation_data JSONB DEFAULT NULL
) RETURNS BOOLEAN AS $$
DECLARE
    old_trust_level INTEGER;
    rows_affected INTEGER;
BEGIN
    -- Get current trust level
    SELECT trust_level INTO old_trust_level 
    FROM workload_trust_levels 
    WHERE spiffe_id = target_spiffe_id;
    
    -- Update trust level
    UPDATE workload_trust_levels 
    SET trust_level = new_trust_level,
        updated_at = NOW()
    WHERE spiffe_id = target_spiffe_id;
    
    GET DIAGNOSTICS rows_affected = ROW_COUNT;
    
    -- Insert audit record if update was successful
    IF rows_affected > 0 THEN
        INSERT INTO workload_trust_audit (
            spiffe_id, old_trust_level, new_trust_level, 
            reason, attestation_data, changed_by
        ) VALUES (
            target_spiffe_id, old_trust_level, new_trust_level,
            reason, attestation_data, changed_by
        );
        RETURN TRUE;
    END IF;
    
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

-- Create function to get effective trust level for SPIFFE ID
CREATE OR REPLACE FUNCTION get_effective_trust_level(
    target_spiffe_id VARCHAR(2048)
) RETURNS INTEGER AS $$
DECLARE
    base_trust_level INTEGER := 25;
    policy_trust_level INTEGER := 25;
    effective_trust_level INTEGER;
BEGIN
    -- Get base trust level from workload_trust_levels
    SELECT trust_level INTO base_trust_level
    FROM workload_trust_levels 
    WHERE spiffe_id = target_spiffe_id;
    
    -- If no specific trust level found, use default
    IF base_trust_level IS NULL THEN
        base_trust_level := 25;
    END IF;
    
    -- Get maximum required trust level from matching policies
    SELECT MAX(required_trust_level) INTO policy_trust_level
    FROM attestation_policies 
    WHERE active = true 
    AND target_spiffe_id ~ spiffe_id_pattern;
    
    -- If no policy matches, use base trust level
    IF policy_trust_level IS NULL THEN
        policy_trust_level := base_trust_level;
    END IF;
    
    -- Return the higher of base or policy-required trust level
    effective_trust_level := GREATEST(base_trust_level, policy_trust_level);
    
    RETURN effective_trust_level;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions on all objects to spire user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO spire;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO spire;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO spire;