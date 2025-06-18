#!/bin/bash
# SPIRE Integration Examples

echo "=== SPIRE Integration Examples ==="

# 1. Check SPIRE Server status
echo "1. SPIRE Server Health:"
curl -s http://localhost:8081/live || echo "SPIRE server not available"

# 2. Register a workload (this would normally be done via SPIRE APIs)
echo "2. SPIRE Workload Registration Example:"
echo "spire-server entry create \\"
echo "  -spiffeID spiffe://mvp.local/envoy \\"
echo "  -parentID spiffe://mvp.local/spire/agent/join_token/$(hostname) \\"
echo "  -selector docker:image_id:envoyproxy/envoy"

# 3. Check agent socket (where Envoy would connect for certificates)
echo "3. SPIRE Agent Socket:"
if [ -S "/tmp/spire-agent/public/api.sock" ]; then
  echo "✓ SPIRE agent socket available"
else
  echo "✗ SPIRE agent socket not found"
fi

# 4. Example SVID fetch (what Envoy would do)
echo "4. Example SVID Fetch:"
echo "grpcurl -unix /tmp/spire-agent/public/api.sock \\"
echo "  spire.api.agent.workloadattestor.v1.WorkloadAttestor/FetchJWTBundles"

# 5. Certificate rotation monitoring
echo "5. Certificate Rotation Example:"
echo "# Envoy would automatically get new certificates from SPIRE"
echo "# Current cert validity can be checked via:"
echo "openssl x509 -in /etc/ssl/certs/server.crt -text -noout | grep 'Not After'"

echo "=== SPIRE Integration Examples Complete ==="