#!/bin/bash

set -e

echo "🔐 Generating development certificates..."

# Create certificates directory if it doesn't exist
mkdir -p certs
mkdir -p envoy/certs
mkdir -p deployments/spire/server
mkdir -p deployments/spire/agent

# Generate Root CA
echo "📜 Generating Root CA..."
openssl genrsa -out certs/ca.key 4096
openssl req -new -x509 -key certs/ca.key -sha256 -subj "/C=US/ST=CA/O=MVP Zero Trust/CN=MVP CA" -days 3650 -out certs/ca.crt

# Generate server certificate for localhost development
echo "🖥️  Generating server certificate..."
openssl genrsa -out certs/server.key 4096
openssl req -subj "/C=US/ST=CA/O=MVP Zero Trust/CN=localhost" -sha256 -new -key certs/server.key -out certs/server.csr

# Create certificate extensions for SAN
cat > certs/server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = mvp.local
DNS.4 = *.mvp.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign the server certificate
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -out certs/server.crt -days 365 -sha256 -extfile certs/server.ext

# Copy certificates to appropriate locations
echo "📋 Copying certificates to service directories..."

# Copy to SPIRE directories
cp certs/ca.key deployments/spire/server/ca.key
cp certs/ca.crt deployments/spire/server/ca.crt

# Copy to Envoy directory
cp certs/ca.crt envoy/certs/ca.crt
cp certs/server.crt envoy/certs/server.crt
cp certs/server.key envoy/certs/server.key

# Set appropriate file permissions
chmod 600 certs/*.key
chmod 600 deployments/spire/server/ca.key
chmod 600 envoy/certs/server.key
chmod 644 certs/*.crt
chmod 644 deployments/spire/server/ca.crt
chmod 644 envoy/certs/*.crt

# Clean up temporary files
rm -f certs/server.csr certs/server.ext certs/ca.srl

echo "✅ Development certificates generated successfully!"
echo "📁 Certificates stored in:"
echo "   - ./certs/ (main certificates)"
echo "   - ./deployments/spire/server/ (SPIRE CA certificates)"
echo "   - ./envoy/certs/ (Envoy proxy certificates)"
echo ""
echo "⚠️  These are development certificates only - DO NOT use in production!"