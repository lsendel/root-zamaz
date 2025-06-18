#!/bin/bash
# Envoy Observability Examples

echo "=== Envoy Observability Examples ==="

# 1. Key Metrics Collection
echo "1. Collecting key Envoy metrics..."

echo "Request Metrics:"
curl -s http://localhost:9901/stats | grep -E "downstream_rq_(total|complete|active)"

echo -e "\nUpstream Health:"
curl -s http://localhost:9901/stats | grep -E "cluster.*health_check"

echo -e "\nConnection Stats:"
curl -s http://localhost:9901/stats | grep -E "listener.*connection"

# 2. Access Logs (if configured)
echo -e "\n2. Access Log Format Example:"
echo '{
  "start_time": "%START_TIME%",
  "method": "%REQ(:METHOD)%", 
  "path": "%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%",
  "protocol": "%PROTOCOL%",
  "response_code": "%RESPONSE_CODE%",
  "response_flags": "%RESPONSE_FLAGS%",
  "bytes_received": "%BYTES_RECEIVED%",
  "bytes_sent": "%BYTES_SENT%",
  "duration": "%DURATION%",
  "upstream_service_time": "%RESP(X-ENVOY-UPSTREAM-SERVICE-TIME)%",
  "x_forwarded_for": "%REQ(X-FORWARDED-FOR)%",
  "user_agent": "%REQ(USER-AGENT)%",
  "request_id": "%REQ(X-REQUEST-ID)%",
  "authority": "%REQ(:AUTHORITY)%",
  "upstream_host": "%UPSTREAM_HOST%"
}'

# 3. Circuit Breaker Stats
echo -e "\n3. Circuit Breaker Status:"
curl -s http://localhost:9901/stats | grep -E "cluster.*circuit_breakers"

# 4. Retry and Timeout Stats  
echo -e "\n4. Retry and Timeout Stats:"
curl -s http://localhost:9901/stats | grep -E "(retry|timeout)"

# 5. TLS Stats (when mTLS is enabled)
echo -e "\n5. TLS Connection Stats:"
curl -s http://localhost:9901/stats | grep -E "ssl\.(ciphers|curves|versions)"

# 6. Memory and Performance
echo -e "\n6. Memory Usage:"
curl -s http://localhost:9901/stats | grep -E "server\.(memory|uptime)"

# 7. Generate sample traffic for testing
echo -e "\n7. Generating sample traffic for metrics..."
for i in {1..10}; do
  curl -s http://localhost:8080/health > /dev/null
  curl -s http://localhost:8080/api/auth/me > /dev/null  
done

echo -e "\n8. Updated Request Metrics:"
curl -s http://localhost:9901/stats | grep "downstream_rq_total"

echo -e "\n=== Observability Examples Complete ==="