-- Initial database setup for MVP Zero Trust Auth System
-- This file contains the initial database schema and data

-- Create SPIRE user and database for SPIRE server
-- Note: This runs as the postgres superuser during container initialization

-- Create SPIRE user
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'spire') THEN
        CREATE USER spire WITH PASSWORD 'spire';
    END IF;
END
$$;

-- Create SPIRE database
SELECT 'CREATE DATABASE spire OWNER spire'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'spire')\gexec

-- Grant privileges to SPIRE user
GRANT ALL PRIVILEGES ON DATABASE spire TO spire;

-- Now create application tables in the mvp_db database
-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Sessions table for session management
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Device attestation table for zero trust
CREATE TABLE IF NOT EXISTS device_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255) NOT NULL,
    attestation_data JSONB NOT NULL,
    trust_level INTEGER DEFAULT 0,
    is_verified BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, device_id)
);

-- Audit log table for security events
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(100) NOT NULL,
    event_data JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_attestations_user_id ON device_attestations(user_id);
CREATE INDEX IF NOT EXISTS idx_device_attestations_device_id ON device_attestations(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Insert default admin user (for development only)
INSERT INTO users (username, email, password_hash, is_active) VALUES 
('admin', 'admin@mvp.local', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', true)
ON CONFLICT (username) DO NOTHING;

-- Log the completion
INSERT INTO audit_logs (event_type, event_data) VALUES 
('database_migration', JSONB_BUILD_OBJECT('version', 'initial', 'timestamp', EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)));