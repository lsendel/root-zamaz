#!/bin/bash
# Load testing through Envoy proxy

echo "=== Load Testing Envoy Proxy ==="

# Test 1: Basic health check load
echo "1. Health check load test..."
for i in {1..100}; do
  curl -s http://localhost:8080/health > /dev/null &
done
wait

# Test 2: Authentication load  
echo "2. Authentication load test..."
for i in {1..50}; do
  curl -s -X POST http://localhost:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"password"}' > /dev/null &
done
wait

# Test 3: Check Envoy stats after load
echo "3. Envoy stats after load:"
curl -s http://localhost:9901/stats | grep -E "(downstream_rq_total|upstream_rq_total|health_check)"

echo "=== Load test complete ==="