# API Documentation

The Zero Trust Auth MVP provides a comprehensive REST API for authentication, device management, and system administration.

## 🌐 Base Information

- **Base URL**: `http://localhost:8080/api`
- **Content Type**: `application/json`
- **Authentication**: Bearer JWT tokens
- **API Version**: v1.0
- **Swagger UI**: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

## 🔐 Authentication

### Overview
The API uses JWT (JSON Web Tokens) for authentication with a dual-token approach:
- **Access Token**: Short-lived (24h default) for API access
- **Refresh Token**: Long-lived for obtaining new access tokens

### Authentication Flow
```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Database

    Client->>API: POST /api/auth/login (username, password)
    API->>Database: Validate credentials
    Database-->>API: User data
    API-->>Client: JWT access + refresh tokens

    Client->>API: GET /api/protected (Authorization: Bearer token)
    API->>API: Validate JWT
    API-->>Client: Protected resource

    Note over Client,API: When access token expires
    Client->>API: POST /api/auth/refresh (refresh token)
    API-->>Client: New access token
```

## 📚 API Endpoints

### Authentication Endpoints

#### `POST /api/auth/login`
Authenticate user and obtain JWT tokens.

**Request:**
```json
{
  "username": "admin",
  "password": "password"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "admin",
    "email": "admin@localhost",
    "first_name": "Admin",
    "last_name": "User",
    "is_active": true,
    "is_admin": true,
    "created_at": "2024-01-15T10:30:45Z"
  }
}
```

**Error Response (401 Unauthorized):**
```json
{
  "error": "Invalid credentials",
  "message": "Username or password is incorrect"
}
```

#### `POST /api/auth/register`
Register a new user account.

**Request:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "securepassword",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response (201 Created):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "newuser",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "is_active": true,
  "is_admin": false,
  "created_at": "2024-01-15T10:30:45Z"
}
```

#### `POST /api/auth/refresh`
Refresh access token using refresh token.

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400
}
```

#### `GET /api/auth/me`
Get current authenticated user information.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "admin",
  "email": "admin@localhost",
  "first_name": "Admin",
  "last_name": "User",
  "is_active": true,
  "is_admin": true,
  "roles": ["admin", "user"],
  "permissions": ["system:admin", "device:verify"],
  "created_at": "2024-01-15T10:30:45Z"
}
```

#### `POST /api/auth/logout`
Invalidate current session and tokens.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
{
  "message": "Successfully logged out"
}
```

#### `POST /api/auth/change-password`
Change user password.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request:**
```json
{
  "current_password": "oldpassword",
  "new_password": "newpassword"
}
```

**Response (200 OK):**
```json
{
  "message": "Password changed successfully"
}
```

### Device Management Endpoints

#### `GET /api/devices`
Get all device attestations for the authenticated user.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
[
  {
    "id": "1",
    "device_id": "device-001",
    "device_name": "MacBook Pro",
    "trust_level": 85,
    "is_verified": true,
    "verified_at": "2024-01-15T10:30:45Z",
    "platform": "macOS",
    "spiffe_id": "spiffe://mvp.local/device/device-001",
    "attestation_data": {
      "tpm": "enabled",
      "secure_boot": "enabled",
      "biometric": "enabled"
    },
    "created_at": "2024-01-15T10:00:00Z",
    "updated_at": "2024-01-15T10:30:45Z"
  }
]
```

#### `POST /api/devices`
Create a new device attestation.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request:**
```json
{
  "device_id": "device-002",
  "device_name": "iPhone 14",
  "platform": "iOS",
  "spiffe_id": "spiffe://mvp.local/device/device-002",
  "workload_selector": "device:mobile",
  "attestation_data": {
    "secure_enclave": "enabled",
    "biometric": "face_id",
    "jailbreak_detection": "passed"
  }
}
```

**Response (201 Created):**
```json
{
  "id": "2",
  "device_id": "device-002",
  "device_name": "iPhone 14",
  "trust_level": 70,
  "is_verified": false,
  "platform": "iOS",
  "spiffe_id": "spiffe://mvp.local/device/device-002",
  "workload_selector": "device:mobile",
  "attestation_data": {
    "secure_enclave": "enabled",
    "biometric": "face_id",
    "jailbreak_detection": "passed"
  },
  "created_at": "2024-01-15T11:00:00Z",
  "updated_at": "2024-01-15T11:00:00Z"
}
```

#### `GET /api/devices/{id}`
Get specific device by ID.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
{
  "id": "1",
  "device_id": "device-001",
  "device_name": "MacBook Pro",
  "trust_level": 85,
  "is_verified": true,
  "verified_at": "2024-01-15T10:30:45Z",
  "platform": "macOS",
  "spiffe_id": "spiffe://mvp.local/device/device-001",
  "attestation_data": {
    "tpm": "enabled",
    "secure_boot": "enabled",
    "biometric": "enabled"
  },
  "created_at": "2024-01-15T10:00:00Z",
  "updated_at": "2024-01-15T10:30:45Z"
}
```

#### `PUT /api/devices/{id}`
Update device information.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request:**
```json
{
  "device_name": "MacBook Pro M2",
  "attestation_data": {
    "tpm": "enabled",
    "secure_boot": "enabled",
    "biometric": "enabled",
    "secure_enclave": "enabled"
  }
}
```

**Response (200 OK):**
```json
{
  "id": "1",
  "device_id": "device-001",
  "device_name": "MacBook Pro M2",
  "trust_level": 85,
  "is_verified": true,
  "verified_at": "2024-01-15T10:30:45Z",
  "platform": "macOS",
  "updated_at": "2024-01-15T11:30:00Z"
}
```

#### `DELETE /api/devices/{id}`
Delete device attestation.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
{
  "message": "Device deleted successfully"
}
```

#### `POST /api/devices/{id}/verify`
Verify device attestation (requires device.verify permission).

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request:**
```json
{
  "trust_level": 95
}
```

**Response (200 OK):**
```json
{
  "id": "1",
  "device_id": "device-001",
  "device_name": "MacBook Pro",
  "trust_level": 95,
  "is_verified": true,
  "verified_at": "2024-01-15T11:45:00Z",
  "platform": "macOS",
  "updated_at": "2024-01-15T11:45:00Z"
}
```

### Admin Management Endpoints

#### `GET /api/admin/roles`
List all roles in the system.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "name": "admin",
    "description": "Administrator role",
    "is_active": true
  },
  {
    "id": 2,
    "name": "user",
    "description": "Standard user role",
    "is_active": true
  }
]
```

#### `POST /api/admin/roles`
Create a new role.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request:**
```json
{
  "name": "moderator",
  "description": "Moderator role with limited admin privileges"
}
```

**Response (201 Created):**
```json
{
  "id": 3,
  "name": "moderator",
  "description": "Moderator role with limited admin privileges",
  "is_active": true
}
```

#### `GET /api/admin/users`
List all users in the system.

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "admin",
    "email": "admin@localhost",
    "first_name": "Admin",
    "last_name": "User",
    "is_active": true,
    "is_admin": true,
    "created_at": "2024-01-15T10:30:45Z"
  }
]
```

### System Endpoints

#### `GET /health`
Basic health check (public endpoint).

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T11:45:00Z",
  "services": {
    "database": {
      "status": "healthy",
      "last_check": "2024-01-15T11:45:00Z",
      "response_time": "2ms"
    },
    "redis": {
      "status": "healthy",
      "last_check": "2024-01-15T11:45:00Z",
      "response_time": "1ms"
    }
  }
}
```

#### `GET /api/system/health`
Detailed system health information (requires authentication).

**Headers:**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T11:45:00Z",
  "services": {
    "database": {
      "status": "healthy",
      "last_check": "2024-01-15T11:45:00Z",
      "response_time": "2ms",
      "details": {
        "open_connections": 5,
        "max_connections": 100,
        "version": "PostgreSQL 15.3"
      }
    },
    "redis": {
      "status": "healthy",
      "last_check": "2024-01-15T11:45:00Z",
      "response_time": "1ms",
      "details": {
        "memory": "1.2MB",
        "connected_clients": 3,
        "version": "7.0.11"
      }
    },
    "nats": {
      "status": "healthy",
      "last_check": "2024-01-15T11:45:00Z",
      "response_time": "1ms",
      "details": {
        "note": "NATS health check not implemented"
      }
    },
    "spire": {
      "status": "degraded",
      "last_check": "2024-01-15T11:45:00Z",
      "response_time": "5ms",
      "details": {
        "note": "SPIRE integration not fully implemented"
      }
    }
  }
}
```

## 🔒 Security Headers

All API responses include security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`

## 📊 Rate Limiting

The API implements rate limiting to prevent abuse:
- **Authentication endpoints**: 10 requests per minute per IP
- **General API**: 100 requests per minute per user
- **Admin endpoints**: 50 requests per minute per admin user

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642252800
```

## ❌ Error Handling

### Standard Error Response Format
```json
{
  "error": "Error Type",
  "message": "Detailed error message",
  "timestamp": "2024-01-15T11:45:00Z",
  "path": "/api/auth/login",
  "trace_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### HTTP Status Codes
- `200 OK` - Successful request
- `201 Created` - Resource created successfully
- `204 No Content` - Successful request with no response body
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Authentication required or invalid
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict (e.g., duplicate username)
- `422 Unprocessable Entity` - Validation errors
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error

### Common Error Examples

#### Validation Error (422)
```json
{
  "error": "Validation Failed",
  "message": "Request validation failed",
  "details": {
    "username": ["Username is required"],
    "email": ["Email format is invalid"]
  }
}
```

#### Authentication Error (401)
```json
{
  "error": "Unauthorized",
  "message": "Invalid or expired token"
}
```

#### Permission Error (403)
```json
{
  "error": "Forbidden",
  "message": "Insufficient permissions to access this resource"
}
```

#### Rate Limit Error (429)
```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Try again in 60 seconds.",
  "retry_after": 60
}
```

## 🧪 Testing the API

### Using curl

#### Login
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

#### Get current user
```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
curl -X GET http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

#### Create device
```bash
curl -X POST http://localhost:8080/api/devices \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "test-device",
    "device_name": "Test Device",
    "platform": "Linux"
  }'
```

### Using Postman

Import the OpenAPI specification from `docs/openapi.yaml` to automatically generate a Postman collection.

### Interactive Testing

Visit the Swagger UI at [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html) for interactive API testing.

## 📝 API Versioning

Currently using implicit v1 versioning. Future versions will use:
- URL versioning: `/api/v2/auth/login`
- Header versioning: `Accept: application/vnd.api+json;version=2`

## 🔄 Pagination

For endpoints returning lists, pagination is supported:

**Request:**
```
GET /api/admin/users?page=1&limit=20&sort=created_at&order=desc
```

**Response:**
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "pages": 5
  }
}
```

## 🔍 Filtering and Search

Many endpoints support filtering and search:

**Examples:**
```
GET /api/devices?platform=macOS&verified=true
GET /api/admin/users?search=john&active=true
GET /api/devices?created_after=2024-01-01&trust_level_min=80
```