#!/bin/bash

set -e

echo "🚀 Setting up Zero-Trust MVP development environment..."

# Check requirements
command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "❌ Docker Compose is required but not installed. Aborting." >&2; exit 1; }

# Create necessary directories
echo "📁 Creating project directories..."
mkdir -p {logs,data,certs}
mkdir -p observability/{prometheus,grafana,loki,jaeger}
mkdir -p deployments/{kubernetes,terraform,helm}

# Generate development certificates
echo "🔐 Generating development certificates..."
./scripts/generate-certs.sh

# Set up environment variables
echo "⚙️ Setting up environment variables..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "📝 Please edit .env file with your configuration"
fi

# Pull required Docker images
echo "📦 Pulling Docker images..."
docker-compose pull

# Start core infrastructure
echo "🏗️ Starting infrastructure services..."
docker-compose up -d spire-server postgres redis nats

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Run database migrations
echo "📊 Running database migrations..."
make db-migrate

# Start observability stack
echo "📊 Starting observability stack..."
docker-compose up -d prometheus grafana loki jaeger

# Start application services
echo "🎯 Starting application services..."
docker-compose up -d

echo "✅ Development environment setup complete!"
echo ""
echo "🔍 Available services:"
echo "  - Grafana: http://localhost:3000 (admin/admin)"
echo "  - Prometheus: http://localhost:9090"
echo "  - Jaeger: http://localhost:16686"
echo "  - Envoy Admin: http://localhost:9901"
echo "  - Frontend: http://localhost:5173"
echo ""
echo "📚 Next steps:"
echo "  1. Edit .env file if needed"
echo "  2. Run 'make logs' to see service logs"
echo "  3. Run 'make test' to run tests"
echo "  4. Visit Grafana to see dashboards"
