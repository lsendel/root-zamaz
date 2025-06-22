-- Initialize Keycloak Database
-- Part of Framework Integration Plan - Week 1

-- Create dedicated database for Keycloak
CREATE DATABASE keycloak;

-- Create dedicated user for Keycloak
CREATE USER keycloak WITH ENCRYPTED PASSWORD 'keycloak123';

-- Grant all privileges on the Keycloak database to the Keycloak user
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;

-- Connect to the keycloak database and set up permissions
\connect keycloak;

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO keycloak;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO keycloak;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO keycloak;

-- Enable UUID extension for better ID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create audit table for trust level changes (for compliance)
CREATE TABLE IF NOT EXISTS user_trust_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) NOT NULL,
    old_trust_level INTEGER,
    new_trust_level INTEGER NOT NULL,
    reason TEXT,
    changed_by VARCHAR(255),
    changed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    device_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT
);

-- Index for performance
CREATE INDEX IF NOT EXISTS idx_user_trust_audit_user_id ON user_trust_audit(user_id);
CREATE INDEX IF NOT EXISTS idx_user_trust_audit_changed_at ON user_trust_audit(changed_at);

-- Grant permissions on audit table
GRANT ALL PRIVILEGES ON TABLE user_trust_audit TO keycloak;