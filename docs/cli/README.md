# Zero Trust CLI (ztcli) - Developer Tool Documentation

The Zero Trust CLI (`ztcli`) is a comprehensive command-line tool for managing and testing the MVP Zero Trust Authentication system. It provides developers and administrators with powerful utilities for authentication testing, user management, token operations, and system administration.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Authentication Commands](#authentication-commands)
- [Token Operations](#token-operations)
- [User Management](#user-management)
- [System Administration](#system-administration)
- [Development Utilities](#development-utilities)
- [Output Formats](#output-formats)
- [Configuration File](#configuration-file)
- [Environment Variables](#environment-variables)
- [Examples & Workflows](#examples--workflows)
- [Troubleshooting](#troubleshooting)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/mvp/zerotrust-auth.git
cd zerotrust-auth

# Build the CLI tool
make build
# or specifically for CLI
go build -o bin/ztcli cmd/ztcli/main.go

# Install to system PATH
sudo cp bin/ztcli /usr/local/bin/
```

### Using Go Install

```bash
go install mvp.local/cmd/ztcli@latest
```

### Pre-built Binaries

Download the latest release from the [releases page](https://github.com/mvp/zerotrust-auth/releases) and place the binary in your PATH.

## Configuration

### Quick Setup

```bash
# Set the base URL and API key
ztcli config --url https://auth.example.com --api-key your-api-key

# Or use environment variables
export ZTCLI_BASE_URL="https://auth.example.com"
export ZTCLI_API_KEY="your-api-key"

# Test the connection
ztcli system health
```

### Global Flags

All commands support these global flags:

- `--url` / `-u`: Zero Trust Auth service URL
- `--api-key`: API key for authentication
- `--output` / `-o`: Output format (table, json, yaml)
- `--verbose` / `-v`: Enable verbose output
- `--config`: Custom config file path

## Authentication Commands

### Login

Authenticate a user and obtain access tokens.

```bash
# Basic login
ztcli auth login user@example.com

# Login with password (non-interactive)
ztcli auth login user@example.com --password mypassword

# Login with MFA
ztcli auth login user@example.com --mfa 123456

# Remember login session
ztcli auth login user@example.com --remember

# Example output
✅ Authentication successful!
Access Token: eyJhbGciOiJSUzI1NiIs...
Expires At: 2024-12-31T23:59:59Z
```

### Logout

Logout from current or all sessions.

```bash
# Logout current session
ztcli auth logout

# Logout specific token
ztcli auth logout --token eyJhbGciOiJSUzI1NiIs...

# Logout from all devices
ztcli auth logout --everywhere

# Example output
✅ Logout successful!
```

### Refresh Token

Refresh an access token using a refresh token.

```bash
# Refresh token
ztcli auth refresh <refresh_token>

# Example output
✅ Token refreshed successfully!
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "expires_at": "2024-12-31T23:59:59Z",
  "token_type": "Bearer"
}
```

## Token Operations

### Validate Token

Validate an access token and view its claims.

```bash
# Basic token validation
ztcli token validate eyJhbGciOiJSUzI1NiIs...

# Validate with required scopes
ztcli token validate eyJhbGciOiJSUzI1NiIs... --scopes read:profile,write:profile

# Validate with audience
ztcli token validate eyJhbGciOiJSUzI1NiIs... --audience api.example.com

# Example output
✅ Token is valid!
{
  "valid": true,
  "claims": {
    "sub": "user-123",
    "email": "user@example.com",
    "roles": ["user", "admin"],
    "scopes": ["read:profile", "write:profile"],
    "iat": 1640995200,
    "exp": 1640998800
  },
  "trust_score": 0.95
}
```

### Token Introspection

Get detailed information about a token (same as validate with full details).

```bash
# Introspect token
ztcli token introspect eyJhbGciOiJSUzI1NiIs...

# Output includes all token metadata
{
  "valid": true,
  "active": true,
  "token_type": "Bearer",
  "claims": {
    "sub": "user-123",
    "email": "user@example.com",
    "roles": ["user"],
    "permissions": ["read:profile", "write:profile"],
    "iat": 1640995200,
    "exp": 1640998800,
    "aud": "api.example.com",
    "iss": "https://auth.example.com"
  },
  "trust_score": 0.95,
  "issued_at": "2024-01-01T00:00:00Z",
  "expires_at": "2024-01-01T01:00:00Z"
}
```

## User Management

### List Users

List users with filtering options.

```bash
# List all users
ztcli user list

# Filter by role
ztcli user list --role admin

# Filter by status
ztcli user list --status active

# Pagination
ztcli user list --limit 10 --offset 0

# Example output
📋 User list functionality not yet implemented
This would connect to the user management API
```

### Create User

Create a new user account.

```bash
# Create basic user
ztcli user create --email newuser@example.com

# Create user with full details
ztcli user create \
  --email admin@example.com \
  --first-name John \
  --last-name Doe \
  --password securepassword \
  --roles admin,user \
  --active \
  --verified

# Example output
📝 Creating user: admin@example.com
Name: John Doe
Password provided: true
Roles: [admin user]
Active: true, Verified: true
🚧 User creation functionality not yet implemented
```

### Show User

Display detailed information about a specific user.

```bash
# Show user by ID
ztcli user show user-123

# Example output
👤 Showing user: user-123
🚧 User show functionality not yet implemented
```

### Update User

Update user information.

```bash
# Update user details
ztcli user update user-123 \
  --first-name Jane \
  --last-name Smith \
  --roles admin \
  --active

# Example output
✏️ Updating user: user-123
🚧 User update functionality not yet implemented
```

### Delete User

Delete a user account.

```bash
# Delete user
ztcli user delete user-123

# Example output
🗑️ Deleting user: user-123
🚧 User deletion functionality not yet implemented
```

## System Administration

### Health Check

Check if the Zero Trust Auth service is healthy.

```bash
# Basic health check
ztcli system health

# Example output
✅ System is healthy!
```

### System Status

Get comprehensive system status including connection details.

```bash
# Show system status
ztcli system status

# Example output
📊 System Status:
Base URL: https://auth.example.com
API Key: your****key
Connection: ✅ Successful
```

### Configuration

Display current CLI configuration.

```bash
# Show current config
ztcli system config

# Example output (JSON format)
{
  "base_url": "https://auth.example.com",
  "api_key": "your-api-key",
  "timeout": "30s",
  "debug": false
}
```

## Development Utilities

### Generate API Key

Generate a new API key for development.

```bash
# Generate API key
ztcli dev generate-key

# Example output
🔑 Generated API Key: dev-api-key-abc123xyz789
💡 Store this key securely and use it for API authentication
```

### Generate SDK Client

Generate SDK client code for different languages.

```bash
# Generate Go SDK
ztcli dev generate-client --lang go --output-dir ./sdk/go

# Generate JavaScript SDK
ztcli dev generate-client --lang javascript --output-dir ./sdk/js --package @company/auth-sdk

# Generate Python SDK
ztcli dev generate-client --lang python --output-dir ./sdk/python --package zerotrust-sdk

# Example output
🔧 Generating go SDK client...
Output directory: ./sdk/go
🚧 Code generation functionality not yet implemented
This would generate SDK client code in the specified language
```

### Test Connection

Test connectivity to the Zero Trust Auth service with timing information.

```bash
# Test connection
ztcli dev test-connection

# Example output
🔗 Testing connection to https://auth.example.com...
✅ Connection successful! Response time: 45ms
```

## Output Formats

The CLI supports multiple output formats for structured data:

### JSON Output

```bash
# Get JSON output
ztcli token validate <token> --output json

{
  "valid": true,
  "claims": {
    "sub": "user-123",
    "email": "user@example.com"
  }
}
```

### YAML Output

```bash
# Get YAML output
ztcli token validate <token> --output yaml

# Currently returns JSON format
# YAML formatting planned for future release
```

### Table Output (Default)

```bash
# Default table format
ztcli token validate <token> --output table

# Returns formatted JSON for now
# Table formatting planned for future release
```

## Configuration File

The CLI uses a YAML configuration file located at `~/.ztcli.yaml` by default.

### Sample Configuration

```yaml
# ~/.ztcli.yaml
base_url: "https://auth.example.com"
api_key: "your-api-key"
timeout: "30s"
debug: false
output_format: "json"

# Optional: Custom user agent
user_agent: "MyApp/1.0 ztcli"

# Optional: TLS settings for development
insecure_skip_verify: false
```

### Custom Config File

```bash
# Use custom config file
ztcli --config /path/to/custom-config.yaml system health
```

## Environment Variables

Override configuration with environment variables:

```bash
# Required variables
export ZTCLI_BASE_URL="https://auth.example.com"
export ZTCLI_API_KEY="your-api-key"

# Optional variables
export ZTCLI_TIMEOUT="30s"
export ZTCLI_DEBUG="true"
export ZTCLI_OUTPUT="json"
export ZTCLI_VERBOSE="true"

# Use the CLI
ztcli system health
```

## Examples & Workflows

### Complete Authentication Flow

```bash
# 1. Test connection
ztcli dev test-connection

# 2. Login user
ztcli auth login user@example.com --password mypassword

# 3. Validate the returned token
ztcli token validate eyJhbGciOiJSUzI1NiIs...

# 4. Check system status
ztcli system status

# 5. Logout
ztcli auth logout
```

### Development Workflow

```bash
# 1. Generate API key for development
ztcli dev generate-key

# 2. Set up configuration
cat > ~/.ztcli.yaml << EOF
base_url: "http://localhost:8080"
api_key: "dev-api-key-abc123"
debug: true
EOF

# 3. Test local development server
ztcli system health

# 4. Test authentication
ztcli auth login dev@example.com --password devpassword

# 5. Generate SDK code
ztcli dev generate-client --lang go --output-dir ./sdk
```

### Token Testing Workflow

```bash
# 1. Login and capture output
LOGIN_RESPONSE=$(ztcli auth login user@example.com --output json)
ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.access_token')
REFRESH_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.refresh_token')

# 2. Validate token
ztcli token validate $ACCESS_TOKEN --scopes read:profile

# 3. Test token with specific audience
ztcli token validate $ACCESS_TOKEN --audience api.example.com

# 4. Refresh token when needed
ztcli auth refresh $REFRESH_TOKEN

# 5. Logout when done
ztcli auth logout --token $ACCESS_TOKEN
```

### System Administration Workflow

```bash
# 1. Check system health
ztcli system health

# 2. Get system status
ztcli system status --output json

# 3. List users (when implemented)
ztcli user list --role admin

# 4. Create admin user (when implemented)
ztcli user create \
  --email admin@company.com \
  --first-name System \
  --last-name Admin \
  --roles admin,user \
  --active \
  --verified

# 5. Monitor system
watch -n 5 'ztcli system health'
```

## Troubleshooting

### Common Issues

#### Connection Failed

```bash
# Problem
❌ Connection failed after 45ms: dial tcp: connect: connection refused

# Solutions
1. Check if the service is running
2. Verify the base URL is correct
3. Check firewall/network settings
4. Verify API key is valid
```

#### Authentication Failed

```bash
# Problem
❌ Authentication failed: invalid credentials

# Solutions
1. Verify email and password are correct
2. Check if account is active
3. Try password reset if needed
4. Verify API key has proper permissions
```

#### Token Validation Failed

```bash
# Problem
❌ Token is invalid!

# Solutions
1. Check if token has expired
2. Verify token format is correct
3. Ensure required scopes are available
4. Check if audience matches
```

#### Configuration Issues

```bash
# Problem
Error initializing client: missing base URL

# Solutions
1. Set ZTCLI_BASE_URL environment variable
2. Use --url flag
3. Create ~/.ztcli.yaml config file
4. Check config file syntax
```

### Debug Mode

Enable verbose output for debugging:

```bash
# Enable debug mode
ztcli --verbose system health

# Or set environment variable
export ZTCLI_DEBUG=true
ztcli system health
```

### Getting Help

```bash
# Show general help
ztcli --help

# Show command-specific help
ztcli auth --help
ztcli auth login --help
ztcli token validate --help

# Show version information
ztcli version  # (if implemented)
```

### Logging

The CLI outputs to stderr for errors and stdout for results:

```bash
# Capture only results
ztcli token validate <token> --output json > token-info.json

# Capture only errors
ztcli system health 2> error.log

# Capture both
ztcli auth login user@example.com > result.json 2> error.log
```

## Integration with Makefile

The CLI integrates with the project's Makefile for common operations:

```bash
# CLI help
make cli-help

# Health check
make cli-health

# System status
make cli-status

# Generate API key
make cli-generate-key

# Test connection
make cli-test-connection
```

For more detailed information about the Zero Trust Authentication system, see the [main documentation](../README.md) and [SDK documentation](../sdk/).