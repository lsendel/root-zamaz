# Troubleshooting Guide

This comprehensive guide helps diagnose and resolve common issues in the Zero Trust Auth MVP.

## 🚨 Quick Diagnosis

### System Health Check

```bash
# Quick health check script
#!/bin/bash
echo "=== Zero Trust Auth System Health Check ==="

# Check Docker
echo "🐳 Docker Status:"
docker --version && echo "✅ Docker OK" || echo "❌ Docker not available"

# Check containers
echo "📦 Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep mvp-zero-trust

# Check services
echo "🌐 Service Health:"
curl -f http://localhost:8080/health && echo "✅ API OK" || echo "❌ API not responding"
curl -f http://localhost:5175 && echo "✅ Frontend OK" || echo "❌ Frontend not responding"

# Check database
echo "🗄️ Database Status:"
docker exec mvp-zero-trust-auth-postgres-1 pg_isready -U mvp_user && echo "✅ DB OK" || echo "❌ DB not ready"

# Check logs for errors
echo "📝 Recent Errors:"
docker logs mvp-zero-trust-auth-envoy-1 --tail 5 2>&1 | grep -i error || echo "No recent errors"
```

### Quick Fixes

```bash
# Nuclear option - restart everything
make dev-down && make clean && make dev-up

# Restart specific service
docker restart mvp-zero-trust-auth-envoy-1

# Check and fix ports
lsof -i :8080 | grep LISTEN  # Find what's using port 8080
kill -9 <PID>                # Kill the process
```

## 🔧 Common Issues

### 1. Authentication Issues

#### Problem: Login fails with "Invalid credentials"

**Symptoms:**
- Frontend shows "Login failed" message
- Backend logs show 401 responses
- User exists in database

**Diagnosis:**
```bash
# Check if admin user exists
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "SELECT username, is_active, created_at FROM users WHERE username = 'admin';"

# Check password hash
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "SELECT username, password_hash FROM users WHERE username = 'admin';"

# Test login API directly
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  -v
```

**Solutions:**
```bash
# Reset admin password
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "UPDATE users SET password_hash = '\$2a\$10\$rZ0cK8YU.ZP7UF1YOV8nSu1KXhx/xH8P' WHERE username = 'admin';"

# Recreate admin user
make db-reset
# Or manually:
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "INSERT INTO users (id, username, password_hash, email, first_name, last_name, is_active, is_admin) 
      VALUES (gen_random_uuid(), 'admin', '\$2a\$10\$rZ0cK8YU.ZP7UF1YOV8nSu', 'admin@localhost', 'Admin', 'User', true, true);"
```

#### Problem: JWT token validation fails

**Symptoms:**
- 401 errors on protected endpoints
- "Invalid token" messages
- Token appears valid but is rejected

**Diagnosis:**
```bash
# Check JWT secret configuration
docker exec mvp-zero-trust-auth-envoy-1 env | grep JWT_SECRET

# Decode JWT token (replace with actual token)
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | base64 -d

# Test token validation
curl -X GET http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -v
```

**Solutions:**
```bash
# Ensure consistent JWT secret
export JWT_SECRET="your-consistent-secret-key"
docker restart mvp-zero-trust-auth-envoy-1

# Clear browser storage and re-login
# In browser console:
localStorage.clear();
sessionStorage.clear();
```

#### Problem: Demo tokens not working

**Symptoms:**
- Demo tokens return 401
- "Demo token not allowed" messages

**Diagnosis:**
```bash
# Check if demo tokens are enabled
grep -r "demo-token" pkg/auth/
grep -r "DISABLE_AUTH" .env

# Test demo token directly
curl -X GET http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer demo-token-admin-123" \
  -v
```

**Solutions:**
```bash
# Ensure demo tokens are enabled in development
export DISABLE_AUTH=false
export ENVIRONMENT=development

# Check middleware configuration
grep -A 10 -B 5 "demo-token" pkg/auth/middleware.go
```

### 2. Database Issues

#### Problem: Database connection refused

**Symptoms:**
- "connection refused" errors
- "failed to connect to database" logs
- Server won't start

**Diagnosis:**
```bash
# Check if PostgreSQL container is running
docker ps | grep postgres

# Check PostgreSQL logs
docker logs mvp-zero-trust-auth-postgres-1

# Test connection manually
docker exec mvp-zero-trust-auth-postgres-1 pg_isready -U mvp_user

# Test from host
psql -h localhost -p 5432 -U mvp_user -d mvp_db
```

**Solutions:**
```bash
# Restart PostgreSQL
docker restart mvp-zero-trust-auth-postgres-1

# Reset database completely
make db-reset

# Check for port conflicts
lsof -i :5432
# Kill conflicting processes if needed

# Start with fresh volumes
make dev-down
docker volume prune -f
make dev-up
```

#### Problem: Database migration errors

**Symptoms:**
- Migration failed logs
- Tables missing or incorrect schema
- "relation does not exist" errors

**Diagnosis:**
```bash
# Check current migrations
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "\dt"  # List tables

# Check migration status
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "SELECT * FROM schema_migrations;" 2>/dev/null || echo "No migration table"

# Check specific table structure
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "\d users"
```

**Solutions:**
```bash
# Force migration
make db-migrate

# Reset and recreate database
make db-reset

# Manual migration check
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -f /docker-entrypoint-initdb.d/migrations.sql
```

### 3. Frontend Issues

#### Problem: Frontend build errors

**Symptoms:**
- npm build fails
- TypeScript compilation errors
- Missing dependencies

**Diagnosis:**
```bash
cd frontend

# Check Node.js version
node --version
npm --version

# Check for dependency issues
npm ls
npm audit

# Check TypeScript configuration
npx tsc --noEmit
```

**Solutions:**
```bash
cd frontend

# Clean install
rm -rf node_modules package-lock.json
npm install

# Fix TypeScript errors
npx tsc --noEmit --skipLibCheck

# Update dependencies
npm update
npm audit fix

# Check for conflicting global packages
npm list -g --depth=0
```

#### Problem: API calls failing from frontend

**Symptoms:**
- CORS errors in browser console
- Network errors
- 404 errors for API endpoints

**Diagnosis:**
```bash
# Check CORS configuration
grep -r "CORS" pkg/
grep -r "AllowedOrigins" .env

# Test API directly
curl -X GET http://localhost:8080/api/auth/me \
  -H "Origin: http://localhost:5175" \
  -H "Authorization: Bearer token" \
  -v

# Check network requests in browser dev tools
# Open browser → F12 → Network tab
```

**Solutions:**
```bash
# Fix CORS configuration
export CORS_ALLOWED_ORIGINS="http://localhost:5175,http://localhost:3000"

# Check proxy configuration in vite.config.ts
cat frontend/vite.config.ts | grep -A 10 proxy

# Restart both frontend and backend
make dev-down && make dev-up
cd frontend && npm run dev
```

### 4. Docker Issues

#### Problem: Containers won't start

**Symptoms:**
- "docker-compose up" fails
- Containers exit immediately
- Port binding errors

**Diagnosis:**
```bash
# Check Docker daemon
docker info

# Check container status
docker ps -a

# Check specific container logs
docker logs mvp-zero-trust-auth-envoy-1

# Check resource usage
docker stats

# Check for port conflicts
netstat -tulpn | grep :8080
```

**Solutions:**
```bash
# Restart Docker daemon (macOS)
killall Docker && open /Applications/Docker.app

# Clean up Docker resources
docker system prune -f
docker volume prune -f
docker network prune -f

# Reset Docker Compose
make dev-down
docker-compose -f docker-compose.yml up -d --force-recreate

# Fix permission issues
sudo chown -R $USER:$USER .
```

#### Problem: Out of disk space

**Symptoms:**
- "no space left on device" errors
- Docker build fails
- Containers crash

**Diagnosis:**
```bash
# Check disk usage
df -h
docker system df

# Check Docker space usage
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"
docker volume ls
```

**Solutions:**
```bash
# Clean up Docker
docker system prune -a -f
docker volume prune -f
docker builder prune -f

# Remove unused images
docker rmi $(docker images -q --filter "dangling=true")

# Remove old containers
docker rm $(docker ps -aq --filter "status=exited")
```

### 5. Performance Issues

#### Problem: Slow API responses

**Symptoms:**
- API calls take > 1 second
- Timeouts
- High CPU usage

**Diagnosis:**
```bash
# Check container resource usage
docker stats

# Check database performance
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "SELECT query, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"

# Monitor API response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8080/api/auth/me

# Create curl-format.txt:
cat > curl-format.txt << 'EOF'
     time_namelookup:  %{time_namelookup}\n
        time_connect:  %{time_connect}\n
     time_appconnect:  %{time_appconnect}\n
    time_pretransfer:  %{time_pretransfer}\n
       time_redirect:  %{time_redirect}\n
  time_starttransfer:  %{time_starttransfer}\n
                     ----------\n
          time_total:  %{time_total}\n
EOF
```

**Solutions:**
```bash
# Increase container resources
# In docker-compose.yml:
# deploy:
#   resources:
#     limits:
#       memory: 1G
#       cpus: '1.0'

# Enable database query optimization
export DB_LOG_LEVEL=debug

# Add database indexes (in migration)
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);"

# Tune PostgreSQL settings
docker exec mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db \
  -c "ALTER SYSTEM SET shared_buffers = '256MB';"
```

## 🔍 Debugging Tools

### Logs Analysis

```bash
# View all logs
make logs

# Filter logs by service
docker logs mvp-zero-trust-auth-envoy-1 2>&1 | grep ERROR

# Follow logs in real-time
docker logs -f mvp-zero-trust-auth-envoy-1

# Search logs for specific patterns
docker logs mvp-zero-trust-auth-envoy-1 2>&1 | grep -i "authentication\|login\|token"

# Export logs for analysis
docker logs mvp-zero-trust-auth-envoy-1 > server.log 2>&1
```

### Database Inspection

```bash
# Connect to database
docker exec -it mvp-zero-trust-auth-postgres-1 psql -U mvp_user -d mvp_db

# Common database queries
\dt                              # List tables
\d users                         # Describe users table
SELECT * FROM users LIMIT 5;    # View user data
SELECT COUNT(*) FROM users;     # Count users

# Check database performance
SELECT schemaname,tablename,attname,n_distinct,correlation 
FROM pg_stats 
WHERE tablename = 'users';

# View active connections
SELECT pid, usename, application_name, client_addr, state 
FROM pg_stat_activity 
WHERE state = 'active';
```

### API Testing

```bash
# Health check
curl -f http://localhost:8080/health

# Authentication test
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  | jq '.'

# Protected endpoint test
TOKEN="your-token-here"
curl -X GET http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.'

# Device endpoint test
curl -X GET http://localhost:8080/api/devices \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.'
```

### Network Debugging

```bash
# Check port connectivity
telnet localhost 8080
nc -zv localhost 8080

# Check DNS resolution
nslookup postgres
nslookup redis

# Network connectivity between containers
docker exec mvp-zero-trust-auth-envoy-1 ping postgres
docker exec mvp-zero-trust-auth-envoy-1 nc -zv postgres 5432

# Check container networks
docker network ls
docker network inspect mvp-zero-trust-auth_mvp-network
```

## 🛠️ Advanced Troubleshooting

### Memory Issues

```bash
# Check memory usage
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"

# Go memory profiling
curl http://localhost:9000/debug/pprof/heap > heap.out
go tool pprof heap.out

# Check for memory leaks
docker exec mvp-zero-trust-auth-envoy-1 top -p 1
```

### Security Issues

```bash
# Check for security vulnerabilities
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Scan Docker images
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image mvp-auth:latest

# Check file permissions
ls -la configs/
ls -la certs/
```

### Configuration Issues

```bash
# Dump current configuration
docker exec mvp-zero-trust-auth-envoy-1 env | sort

# Check environment file
cat .env | grep -v '^#' | sort

# Validate configuration
# Add to your Go code:
// func (c *Config) Validate() error { ... }
```

## 📊 Monitoring and Alerting

### Set up Monitoring

```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Check Grafana dashboards
open http://localhost:3000

# View Jaeger traces
open http://localhost:16686

# Custom metrics query
curl 'http://localhost:9090/api/v1/query?query=up'
```

### Health Monitoring Script

```bash
#!/bin/bash
# scripts/health-monitor.sh

while true; do
    # Check API health
    if curl -f http://localhost:8080/health >/dev/null 2>&1; then
        echo "$(date): ✅ API healthy"
    else
        echo "$(date): ❌ API unhealthy"
        # Send alert or restart service
    fi
    
    # Check database
    if docker exec mvp-zero-trust-auth-postgres-1 pg_isready -U mvp_user >/dev/null 2>&1; then
        echo "$(date): ✅ Database healthy"
    else
        echo "$(date): ❌ Database unhealthy"
    fi
    
    sleep 30
done
```

## 🆘 Emergency Procedures

### Complete System Reset

```bash
#!/bin/bash
# Nuclear option - completely reset everything

echo "🚨 EMERGENCY SYSTEM RESET"
echo "This will delete ALL data. Press Ctrl+C to cancel."
sleep 10

# Stop everything
make dev-down

# Remove all containers
docker rm -f $(docker ps -aq)

# Remove all volumes
docker volume rm -f $(docker volume ls -q)

# Remove all networks
docker network rm $(docker network ls -q) 2>/dev/null || true

# Clean system
docker system prune -a -f

# Remove local data
rm -rf data/ logs/

# Restart from scratch
make dev-setup
make dev-up

echo "✅ System reset complete"
```

### Data Recovery

```bash
# Backup current state before recovery
docker exec mvp-zero-trust-auth-postgres-1 pg_dump -U mvp_user mvp_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore from backup
docker exec -i mvp-zero-trust-auth-postgres-1 psql -U mvp_user mvp_db < backup_file.sql

# Export container data
docker run --rm -v mvp_postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres_backup.tar.gz /data
```

## 📞 Getting Help

### Collecting Debug Information

```bash
#!/bin/bash
# scripts/collect-debug-info.sh

DEBUG_DIR="debug_$(date +%Y%m%d_%H%M%S)"
mkdir -p $DEBUG_DIR

# System information
uname -a > $DEBUG_DIR/system_info.txt
docker --version >> $DEBUG_DIR/system_info.txt
docker-compose --version >> $DEBUG_DIR/system_info.txt

# Container status
docker ps -a > $DEBUG_DIR/containers.txt
docker images > $DEBUG_DIR/images.txt

# Logs
docker logs mvp-zero-trust-auth-envoy-1 > $DEBUG_DIR/server.log 2>&1
docker logs mvp-zero-trust-auth-postgres-1 > $DEBUG_DIR/postgres.log 2>&1

# Configuration
cp .env $DEBUG_DIR/ 2>/dev/null || echo "No .env file" > $DEBUG_DIR/env_missing.txt
cp docker-compose.yml $DEBUG_DIR/

# Network information
docker network ls > $DEBUG_DIR/networks.txt
netstat -tulpn > $DEBUG_DIR/ports.txt

# Create archive
tar czf ${DEBUG_DIR}.tar.gz $DEBUG_DIR/
echo "Debug information collected in ${DEBUG_DIR}.tar.gz"
```

### Support Channels

1. **GitHub Issues**: For bugs and feature requests
2. **Documentation**: Check docs/ directory
3. **Stack Overflow**: Tag with `zero-trust-auth`
4. **Community Discord**: Link in README

### Before Asking for Help

- [ ] Check this troubleshooting guide
- [ ] Search existing GitHub issues
- [ ] Collect debug information
- [ ] Try the system reset procedure
- [ ] Provide minimal reproduction steps

## 📚 Related Documentation

- [Development Setup](docs/development/setup.md)
- [API Documentation](docs/api/README.md)
- [Deployment Guide](docs/deployment/docker.md)
- [Security Configuration](docs/architecture/security.md)