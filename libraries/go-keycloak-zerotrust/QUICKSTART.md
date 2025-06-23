# 🚀 Quick Start Guide

Get the go-keycloak-zerotrust library running in under 5 minutes with this comprehensive quick start guide.

## 📋 Prerequisites

Before you begin, ensure you have:

- **Go 1.21+** installed ([Download Go](https://golang.org/dl/))
- **Docker** and **Docker Compose** installed ([Get Docker](https://docs.docker.com/get-docker/))
- **Git** for cloning the repository
- **curl** for testing API endpoints

### Verify Prerequisites

```bash
# Check Go version
go version

# Check Docker
docker --version
docker-compose --version

# Check other tools
git --version
curl --version
```

## 🛠️ Step 1: Environment Setup

### Clone and Setup

```bash
# Clone the repository
git clone https://github.com/yourorg/go-keycloak-zerotrust.git
cd go-keycloak-zerotrust

# Complete development setup (this will take 2-3 minutes)
make setup
```

The `make setup` command will:
- ✅ Check all dependencies
- 📝 Create `.env` file from template
- 📦 Install Go dependencies
- 🐳 Pull Docker images

### Update Configuration

Edit the `.env` file created in the previous step:

```bash
# Open .env file in your preferred editor
nano .env

# Or use the default values - they work out of the box!
```

**Default configuration works immediately**, but you can customize:
- Keycloak admin credentials
- Trust level thresholds
- Cache settings
- Database settings

## 🚀 Step 2: Start Services

### Start All Services

```bash
# Start Keycloak, PostgreSQL, and Redis
make start
```

This command will:
- 🚀 Start PostgreSQL database
- 🚀 Start Redis cache
- 🚀 Start Keycloak server
- ⏳ Wait for all services to be ready
- 📊 Display service status

**Expected output:**
```
Starting development services...
✅ Services started

⏳ PostgreSQL: ✅ Ready
⏳ Redis: ✅ Ready  
⏳ Keycloak: ✅ Ready

Service Status:
==============
NAME                      COMMAND                  SERVICE             STATUS              PORTS
keycloak-zerotrust-db     "docker-entrypoint.s…"   postgres            running             0.0.0.0:5432->5432/tcp
keycloak-zerotrust-redis  "docker-entrypoint.s…"   redis               running             0.0.0.0:6379->6379/tcp
keycloak-zerotrust-kc     "/opt/keycloak/bin/k…"   keycloak            running             0.0.0.0:8080->8080/tcp

Service URLs:
==============
🔐 Keycloak Admin: http://localhost:8080/admin
📊 Keycloak Metrics: http://localhost:8080/metrics
🗄️  PostgreSQL: localhost:5432
🔴 Redis: localhost:6379

Default Credentials:
====================
👤 Keycloak Admin: admin / admin
🗄️  PostgreSQL: keycloak / keycloak_password
```

### Verify Services are Running

```bash
# Check service status
make services-status

# Or check individual services
curl http://localhost:8080/health
```

## 🔐 Step 3: Configure Keycloak

### Automatic Setup (Recommended)

```bash
# Auto-configure Keycloak with test realm and client
make keycloak-setup
```

This will automatically:
- 🏠 Create a test realm (`zerotrust-test`)
- 🔑 Create a test client (`zerotrust-client`)
- 👤 Create test users with different trust levels
- 🎯 Add Zero Trust claim mappers
- 📝 Update your `.env` file with credentials

**Expected output:**
```
🔐 Keycloak Zero Trust Setup
===========================================

✅ Realm zerotrust-test created successfully
✅ Client zerotrust-client created successfully
✅ Created mapper: trust-level
✅ Created mapper: device-id
✅ Created mapper: device-verified
✅ Created mapper: risk-score
✅ Created user: testuser
✅ Created user: adminuser
✅ Created user: lowtrustuser
✅ Updated .env with new configuration

🎉 Keycloak Setup Complete!
===========================================

📋 Configuration Details:
   🌐 Keycloak URL: http://localhost:8080
   🏠 Realm: zerotrust-test
   🔑 Client ID: zerotrust-client
   🔐 Client Secret: zerotrust-secret-1640995200

👤 Test Users:
   • testuser / password (Trust: 75, Risk: 25.5)
   • adminuser / password (Trust: 90, Risk: 15.0) 
   • lowtrustuser / password (Trust: 20, Risk: 75.0)
```

### Manual Setup (Alternative)

If you prefer manual setup:

1. **Open Keycloak Admin Console**: http://localhost:8080/admin
2. **Login**: admin / admin
3. **Create Realm**: Click "Add realm" → Name: `zerotrust-test`
4. **Create Client**: Clients → Create → Client ID: `zerotrust-client`
5. **Configure Client**: 
   - Access Type: confidential
   - Valid Redirect URIs: `http://localhost:8081/*`
   - Service Accounts Enabled: ON

### Get Keycloak Access Information

```bash
# Display Keycloak access info
make keycloak-info
```

## 🧪 Step 4: Run Tests

### End-to-End Tests

```bash
# Run comprehensive E2E tests
make test-e2e
```

These tests verify:
- ✅ Keycloak connectivity
- ✅ Token validation
- ✅ Device attestation
- ✅ Risk assessment
- ✅ Trust score calculation
- ✅ Middleware integration

**Expected output:**
```
Running end-to-end tests...
=== RUN   TestCompleteWorkflow
=== RUN   TestCompleteWorkflow/Device_Registration
=== RUN   TestCompleteWorkflow/Token_Validation
=== RUN   TestCompleteWorkflow/API_Access
=== RUN   TestCompleteWorkflow/Risk_Assessment
=== RUN   TestCompleteWorkflow/Plugin_Execution
=== RUN   TestCompleteWorkflow/Continuous_Verification
--- PASS: TestCompleteWorkflow (2.34s)
✅ End-to-end tests completed
```

### Unit Tests

```bash
# Run unit tests
make test-unit

# Run integration tests
make test-integration

# Run all tests
make test-all
```

### Performance Tests

```bash
# Run benchmarks
make test-benchmark
```

## 🎯 Step 5: Try Examples

### Basic Gin Example

```bash
# Run basic Gin server example
make run-gin-example

# In another terminal, test the API
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:8081/api/data
```

### Echo Framework Example

```bash
# Run Echo server example
make run-echo-example
```

### Get Test Token

```bash
# Get a test token using the test user
curl -X POST http://localhost:8080/realms/zerotrust-test/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=zerotrust-client" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "username=testuser" \
  -d "password=password"
```

## 📚 Standard Scenarios

### Scenario 1: Basic Authentication

**Use Case**: Simple API protection with JWT validation

```go
// examples/scenarios/basic-auth.go
package main

import (
    "log"
    "github.com/gin-gonic/gin"
    zerotrust "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    // Load configuration from environment
    config, err := zerotrust.LoadConfigFromEnv()
    if err != nil {
        log.Fatal(err)
    }
    
    // Create client
    client, err := zerotrust.NewKeycloakClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Create Gin router with authentication
    r := gin.Default()
    middleware := zerotrust.NewGinMiddleware(client)
    
    // Protected endpoint
    r.GET("/api/data", middleware.Authenticate(), func(c *gin.Context) {
        claims := middleware.GetClaims(c)
        c.JSON(200, gin.H{
            "user_id": claims.UserID,
            "message": "Hello authenticated user!",
        })
    })
    
    log.Println("Server starting on :8081")
    r.Run(":8081")
}
```

**Test the scenario:**
```bash
cd examples/scenarios
go run basic-auth.go

# Test with token
TOKEN="eyJhbGci..." # Get from Step 5
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/data
```

### Scenario 2: Trust Level Authorization

**Use Case**: Different operations require different trust levels

```go
// examples/scenarios/trust-levels.go
package main

import (
    "log"
    "github.com/gin-gonic/gin"
    zerotrust "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    config, _ := zerotrust.LoadConfigFromEnv()
    client, _ := zerotrust.NewKeycloakClient(config)
    defer client.Close()
    
    r := gin.Default()
    middleware := zerotrust.NewGinMiddleware(client)
    
    api := r.Group("/api")
    api.Use(middleware.Authenticate())
    {
        // Public data (trust level 25+)
        api.GET("/public", middleware.RequireTrustLevel(25), func(c *gin.Context) {
            c.JSON(200, gin.H{"data": "public information"})
        })
        
        // Sensitive data (trust level 50+)
        api.GET("/sensitive", middleware.RequireTrustLevel(50), func(c *gin.Context) {
            c.JSON(200, gin.H{"data": "sensitive information"})
        })
        
        // Admin operations (trust level 75+)
        api.POST("/admin", middleware.RequireTrustLevel(75), func(c *gin.Context) {
            c.JSON(200, gin.H{"status": "admin operation completed"})
        })
        
        // Critical operations (trust level 90+)
        api.DELETE("/critical", middleware.RequireTrustLevel(90), func(c *gin.Context) {
            c.JSON(200, gin.H{"status": "critical operation completed"})
        })
    }
    
    r.Run(":8081")
}
```

**Test different trust levels:**
```bash
# Use testuser (trust level 75) - can access public, sensitive, admin
TOKEN_TEST="..." # testuser token
curl -H "Authorization: Bearer $TOKEN_TEST" http://localhost:8081/api/admin

# Use lowtrustuser (trust level 20) - only public access
TOKEN_LOW="..." # lowtrustuser token  
curl -H "Authorization: Bearer $TOKEN_LOW" http://localhost:8081/api/sensitive
# Should return 403 Forbidden
```

### Scenario 3: Device Attestation

**Use Case**: Require device verification for sensitive operations

```go
// examples/scenarios/device-attestation.go
package main

import (
    "log"
    "github.com/gin-gonic/gin"
    zerotrust "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    config, _ := zerotrust.LoadConfigFromEnv()
    client, _ := zerotrust.NewKeycloakClient(config)
    defer client.Close()
    
    r := gin.Default()
    middleware := zerotrust.NewGinMiddleware(client)
    
    api := r.Group("/api")
    api.Use(middleware.Authenticate())
    {
        // Normal operation
        api.GET("/data", func(c *gin.Context) {
            c.JSON(200, gin.H{"data": "normal data"})
        })
        
        // Requires device verification
        api.POST("/transfer", 
            middleware.RequireDeviceVerification(),
            func(c *gin.Context) {
                claims := middleware.GetClaims(c)
                c.JSON(200, gin.H{
                    "status": "transfer completed",
                    "device_verified": claims.DeviceVerified,
                })
            })
    }
    
    r.Run(":8081")
}
```

### Scenario 4: Risk-Based Access Control

**Use Case**: Adaptive security based on risk assessment

```go
// examples/scenarios/risk-based.go
package main

import (
    "log"
    "github.com/gin-gonic/gin"
    zerotrust "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    config, _ := zerotrust.LoadConfigFromEnv()
    client, _ := zerotrust.NewKeycloakClient(config)
    defer client.Close()
    
    r := gin.Default()
    middleware := zerotrust.NewGinMiddleware(client)
    
    api := r.Group("/api")
    api.Use(middleware.Authenticate())
    {
        // Low risk required (score < 50)
        api.GET("/data", middleware.RequireMaxRiskScore(50), func(c *gin.Context) {
            c.JSON(200, gin.H{"data": "low risk data"})
        })
        
        // Very low risk required (score < 25)
        api.POST("/payment", middleware.RequireMaxRiskScore(25), func(c *gin.Context) {
            claims := middleware.GetClaims(c)
            c.JSON(200, gin.H{
                "status": "payment processed",
                "risk_score": claims.RiskScore,
            })
        })
    }
    
    r.Run(":8081")
}
```

### Scenario 5: Multi-Framework Integration

**Use Case**: Using Zero Trust across different Go frameworks

#### Gin Framework
```go
// Already shown above
```

#### Echo Framework
```go
// examples/scenarios/echo-integration.go
package main

import (
    "net/http"
    "github.com/labstack/echo/v4"
    zerotrust "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    config, _ := zerotrust.LoadConfigFromEnv()
    client, _ := zerotrust.NewKeycloakClient(config)
    defer client.Close()
    
    e := echo.New()
    middleware := zerotrust.NewEchoMiddleware(client)
    
    // Protected routes
    api := e.Group("/api")
    api.Use(middleware.Authenticate())
    api.GET("/data", func(c echo.Context) error {
        claims := middleware.GetClaims(c)
        return c.JSON(http.StatusOK, map[string]interface{}{
            "user_id": claims.UserID,
            "trust_level": claims.TrustLevel,
        })
    }, middleware.RequireTrustLevel(25))
    
    e.Start(":8082")
}
```

#### gRPC Service
```go
// examples/scenarios/grpc-service.go
package main

import (
    "context"
    "log"
    "net"
    "google.golang.org/grpc"
    zerotrust "github.com/yourorg/go-keycloak-zerotrust"
)

func main() {
    config, _ := zerotrust.LoadConfigFromEnv()
    client, _ := zerotrust.NewKeycloakClient(config)
    defer client.Close()
    
    interceptor := zerotrust.NewGRPCInterceptor(client)
    
    s := grpc.NewServer(
        grpc.UnaryInterceptor(interceptor.UnaryInterceptor()),
        grpc.StreamInterceptor(interceptor.StreamInterceptor()),
    )
    
    // Register your gRPC services here
    
    lis, err := net.Listen("tcp", ":9090")
    if err != nil {
        log.Fatal(err)
    }
    
    log.Println("gRPC server starting on :9090")
    s.Serve(lis)
}
```

## 🔧 Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check if ports are in use
netstat -tlnp | grep :8080
netstat -tlnp | grep :5432
netstat -tlnp | grep :6379

# Clean and restart
make clean-docker
make start
```

#### Keycloak Not Ready
```bash
# Check Keycloak logs
make logs-keycloak

# Wait longer for startup
sleep 60
make wait-for-services
```

#### Test Failures
```bash
# Check service status
make services-status

# Verify environment configuration
cat .env

# Re-run Keycloak setup
make keycloak-reset
make keycloak-setup
```

#### Connection Issues
```bash
# Test connectivity
curl http://localhost:8080/health
curl http://localhost:8080/admin

# Check Docker network
docker network ls
docker network inspect go-keycloak-zerotrust_zerotrust-network
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=debug

# Run tests with verbose output
make test-e2e -v

# Check detailed logs
make logs
```

### Getting Help

1. **Check logs**: `make logs`
2. **Verify configuration**: `cat .env`
3. **Run health checks**: `make services-status`
4. **Reset environment**: `make reset`

## 🎯 Next Steps

### Development
- Explore the [examples/](examples/) directory
- Read the [API Reference](docs/api-reference.md)
- Check out [framework integrations](docs/frameworks/)

### Production
- Review [Security Guide](docs/security.md)
- Set up [monitoring](docs/monitoring.md)
- Plan [deployment](docs/deployment.md)

### Contributing
- Read the [Contributing Guide](CONTRIBUTING.md)
- Set up development environment
- Run the full test suite

## 📞 Support

- 📖 **Documentation**: [docs/](docs/)
- 🐛 **Issues**: [GitHub Issues](https://github.com/yourorg/go-keycloak-zerotrust/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yourorg/go-keycloak-zerotrust/discussions)
- 📧 **Email**: support@yourorg.com

---

**🎉 Congratulations!** You now have a fully functional Zero Trust authentication system running locally. Start building secure applications with confidence!