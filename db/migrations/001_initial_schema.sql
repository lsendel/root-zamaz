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
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    is_active BOOLEAN DEFAULT true,
    is_admin BOOLEAN DEFAULT false,
    -- Account security fields for lockout protection
    failed_login_attempts INTEGER DEFAULT 0,
    last_failed_login_at TIMESTAMP WITH TIME ZONE,
    account_locked_at TIMESTAMP WITH TIME ZONE,
    account_locked_until TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip VARCHAR(45),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- User sessions table for session management
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    device_id VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    location VARCHAR(100),
    trust_level INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Device attestation table for zero trust
CREATE TABLE IF NOT EXISTS device_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(100) NOT NULL,
    device_name VARCHAR(100),
    attestation_data JSONB,
    trust_level INTEGER DEFAULT 0,
    is_verified BOOLEAN DEFAULT false,
    platform VARCHAR(50),
    spiffe_id VARCHAR(200),
    workload_selector VARCHAR(200),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE,
    verified_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(device_id)
);

-- Roles table for RBAC
CREATE TABLE IF NOT EXISTS roles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description VARCHAR(200),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Permissions table for RBAC
CREATE TABLE IF NOT EXISTS permissions (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description VARCHAR(200),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- User-Role many-to-many relationship
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Role-Permission many-to-many relationship
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- Login attempts table for security tracking and brute force protection
CREATE TABLE IF NOT EXISTS login_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL,
    user_id UUID REFERENCES users(id),
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(500),
    success BOOLEAN DEFAULT false,
    failure_reason VARCHAR(200),
    is_suspicious BOOLEAN DEFAULT false,
    blocked_by_rate BOOLEAN DEFAULT false,
    request_id VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit log table for security events
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    details JSONB,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    request_id VARCHAR(100),
    success BOOLEAN DEFAULT false,
    error_msg VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);
CREATE INDEX IF NOT EXISTS idx_users_account_locked_until ON users(account_locked_until);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_attestations_user_id ON device_attestations(user_id);
CREATE INDEX IF NOT EXISTS idx_device_attestations_device_id ON device_attestations(device_id);
-- Login attempts indexes for security lookups
CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_id ON login_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_address ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_success ON login_attempts(success);
CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at ON login_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_suspicious ON login_attempts(is_suspicious);
-- Composite indexes for common security queries
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_success_time ON login_attempts(ip_address, success, created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_username_success_time ON login_attempts(username, success, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);

-- Insert default admin user (for development only)
-- Password is 'password' (bcrypt hash)
INSERT INTO users (username, email, password_hash, first_name, last_name, is_active, is_admin) VALUES 
('admin', 'admin@mvp.local', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Admin', 'User', true, true)
ON CONFLICT (username) DO NOTHING;

-- Insert default roles
INSERT INTO roles (name, description, is_active) VALUES 
('admin', 'Administrator role with full access', true),
('user', 'Regular user role', true)
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (name, resource, action, description) VALUES 
('system.admin', 'system', 'admin', 'Full system administration access'),
('device.verify', 'device', 'verify', 'Verify device attestation'),
('user.read', 'user', 'read', 'Read user information'),
('user.write', 'user', 'write', 'Write user information')
ON CONFLICT (name) DO NOTHING;

-- Assign admin role to admin user
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id 
FROM users u, roles r 
WHERE u.username = 'admin' AND r.name = 'admin'
ON CONFLICT DO NOTHING;

-- Assign all permissions to admin role
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id 
FROM roles r, permissions p 
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

-- Log the completion
INSERT INTO audit_logs (action, resource, details, success) VALUES 
('database_migration', 'system', JSONB_BUILD_OBJECT('version', 'initial', 'timestamp', EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)), true);
