# Integration Tests

This directory contains integration tests for the MVP Zero Trust Auth system.

## Test Structure

### Infrastructure Tests (`infrastructure_test.go`)
Tests connectivity and basic functionality of external dependencies:
- **PostgreSQL**: Database connectivity and ping
- **Redis**: Cache connectivity and ping  
- **NATS**: Message broker connectivity
- **Observability Stack**: Prometheus, Grafana, Jaeger health endpoints
- **SPIRE**: Identity workload attestation server health

### Observability Tests (`observability_test.go`)
Tests the observability system integration:
- **Initialization**: Observability components setup
- **Metrics Collection**: Security metrics recording and collection
- **Distributed Tracing**: Span creation and context propagation
- **NATS Messaging**: Event publishing with distributed tracing
- **Structured Logging**: JSON logging and correlation IDs

## Running Tests

### Prerequisites
For infrastructure tests, the full Docker Compose environment must be running:
```bash
make dev-up
```

For observability tests, no external dependencies are required (they run in isolation).

### Running All Integration Tests
```bash
make test-integration
```

### Running Specific Test Suites
```bash
# Run only observability tests (no external dependencies)
go test -tags=integration -v ./tests/integration/... -run TestObservabilityIntegration

# Run only infrastructure tests (requires Docker environment)
go test -tags=integration -v ./tests/integration/... -run TestInfrastructureIntegration
```

### Running in Short Mode
Skip integration tests when running with `-short` flag:
```bash
go test -short -v ./tests/integration/...
```

## Helper Functions

The integration tests include several helper functions:

- `setupTestDB(t)` - Connects to PostgreSQL test database
- `setupTestRedis(t)` - Connects to Redis test instance  
- `setupTestNATS(t)` - Connects to NATS test server
- `httpGet(url)` - Makes HTTP GET requests with timeout

## Test Dependencies

The integration tests require these additional Go modules:
- `github.com/lib/pq` - PostgreSQL driver
- `github.com/redis/go-redis/v9` - Redis client
- `github.com/testcontainers/testcontainers-go/modules/compose` - Docker Compose integration

## Notes

- Tests automatically skip when external dependencies are unavailable
- Infrastructure tests use Docker Compose for consistent environment setup
- Observability tests are designed to run without external dependencies
- All tests include proper cleanup with `t.Cleanup()` functions