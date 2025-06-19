# Integration Examples for Zero Trust Authentication

This directory contains practical integration examples for various frameworks and technologies with the MVP Zero Trust Authentication system. These examples demonstrate real-world usage patterns and best practices.

## Table of Contents

- [Frontend Frameworks](#frontend-frameworks)
- [Backend Frameworks](#backend-frameworks)
- [Mobile Applications](#mobile-applications)
- [API Gateways & Proxies](#api-gateways--proxies)
- [Infrastructure & DevOps](#infrastructure--devops)
- [Database Integration](#database-integration)
- [Monitoring & Observability](#monitoring--observability)

## Frontend Frameworks

### React Applications
- [React SPA with Hooks](./frontend/react-spa/) - Complete single-page application
- [React + TypeScript](./frontend/react-typescript/) - Type-safe React integration
- [Next.js SSR](./frontend/nextjs-ssr/) - Server-side rendering with authentication
- [React Native Mobile](./mobile/react-native/) - Mobile app integration

### Vue.js Applications
- [Vue 3 Composition API](./frontend/vue3-composition/) - Modern Vue.js integration
- [Nuxt.js SSR](./frontend/nuxtjs-ssr/) - Universal Vue.js application
- [Vue 2 Options API](./frontend/vue2-options/) - Legacy Vue.js integration

### Angular Applications
- [Angular with Guards](./frontend/angular-guards/) - Route protection with guards
- [Angular Interceptors](./frontend/angular-interceptors/) - HTTP interceptor integration

### Other Frontend
- [Vanilla JavaScript](./frontend/vanilla-js/) - Pure JavaScript integration
- [Svelte Application](./frontend/svelte/) - Svelte framework integration
- [Web Components](./frontend/web-components/) - Custom elements integration

## Backend Frameworks

### Go Frameworks
- [Fiber Web Framework](./backend/go-fiber/) - High-performance Go web server
- [Gin Framework](./backend/go-gin/) - Lightweight Go web framework
- [Echo Framework](./backend/go-echo/) - Minimalist Go web framework
- [Standard HTTP](./backend/go-stdlib/) - Go standard library HTTP server

### Node.js Frameworks
- [Express.js](./backend/nodejs-express/) - Traditional Express.js server
- [Fastify](./backend/nodejs-fastify/) - High-performance Node.js server
- [Koa.js](./backend/nodejs-koa/) - Modern Node.js framework
- [NestJS](./backend/nodejs-nestjs/) - Enterprise Node.js framework

### Python Frameworks
- [FastAPI](./backend/python-fastapi/) - Modern Python API framework
- [Django](./backend/python-django/) - Full-featured Python framework
- [Flask](./backend/python-flask/) - Micro Python framework
- [Starlette](./backend/python-starlette/) - ASGI Python framework

### Other Backend Languages
- [ASP.NET Core](./backend/dotnet-core/) - .NET Core integration
- [Spring Boot](./backend/java-spring/) - Java Spring Boot integration
- [Ruby on Rails](./backend/ruby-rails/) - Ruby framework integration
- [PHP Laravel](./backend/php-laravel/) - PHP framework integration

## Mobile Applications

### Native Mobile
- [iOS Swift](./mobile/ios-swift/) - Native iOS integration
- [Android Kotlin](./mobile/android-kotlin/) - Native Android integration

### Cross-Platform
- [React Native](./mobile/react-native/) - Cross-platform mobile apps
- [Flutter](./mobile/flutter/) - Google's mobile framework
- [Ionic](./mobile/ionic/) - Hybrid mobile applications

## API Gateways & Proxies

### Popular Gateways
- [Kong Gateway](./gateways/kong/) - Kong API Gateway integration
- [Envoy Proxy](./gateways/envoy/) - Cloud-native proxy
- [NGINX](./gateways/nginx/) - NGINX reverse proxy
- [Traefik](./gateways/traefik/) - Modern reverse proxy

### Cloud Gateways
- [AWS API Gateway](./gateways/aws-api-gateway/) - Amazon API Gateway
- [Google Cloud Endpoints](./gateways/gcp-endpoints/) - Google Cloud integration
- [Azure API Management](./gateways/azure-apim/) - Microsoft Azure integration

## Infrastructure & DevOps

### Container Orchestration
- [Kubernetes](./infrastructure/kubernetes/) - K8s deployment and RBAC
- [Docker Compose](./infrastructure/docker-compose/) - Local development stack
- [Docker Swarm](./infrastructure/docker-swarm/) - Docker orchestration

### Service Mesh
- [Istio](./infrastructure/istio/) - Service mesh integration
- [Linkerd](./infrastructure/linkerd/) - Lightweight service mesh
- [Consul Connect](./infrastructure/consul-connect/) - HashiCorp service mesh

### CI/CD Pipelines
- [GitHub Actions](./cicd/github-actions/) - GitHub CI/CD integration
- [GitLab CI](./cicd/gitlab-ci/) - GitLab pipeline integration
- [Jenkins](./cicd/jenkins/) - Jenkins pipeline integration
- [Azure DevOps](./cicd/azure-devops/) - Microsoft DevOps integration

## Database Integration

### SQL Databases
- [PostgreSQL](./database/postgresql/) - Advanced PostgreSQL integration
- [MySQL](./database/mysql/) - MySQL database integration
- [SQLite](./database/sqlite/) - Lightweight database integration

### NoSQL Databases
- [MongoDB](./database/mongodb/) - Document database integration
- [Redis](./database/redis/) - In-memory cache integration
- [Cassandra](./database/cassandra/) - Distributed database integration

### Cloud Databases
- [AWS RDS](./database/aws-rds/) - Amazon RDS integration
- [Google Cloud SQL](./database/gcp-cloudsql/) - Google Cloud database
- [Azure SQL](./database/azure-sql/) - Microsoft Azure database

## Monitoring & Observability

### Metrics & Monitoring
- [Prometheus](./monitoring/prometheus/) - Metrics collection and alerting
- [Grafana](./monitoring/grafana/) - Visualization and dashboards
- [Datadog](./monitoring/datadog/) - Cloud monitoring platform

### Logging
- [ELK Stack](./monitoring/elk-stack/) - Elasticsearch, Logstash, Kibana
- [Fluentd](./monitoring/fluentd/) - Log collection and forwarding
- [Jaeger](./monitoring/jaeger/) - Distributed tracing

### Application Performance
- [New Relic](./monitoring/newrelic/) - APM platform integration
- [AppDynamics](./monitoring/appdynamics/) - Performance monitoring
- [OpenTelemetry](./monitoring/opentelemetry/) - Observability framework

## Getting Started

Each example includes:

1. **README.md** - Detailed setup and usage instructions
2. **Source Code** - Complete, runnable example
3. **Configuration** - Environment and deployment configs
4. **Documentation** - Architecture and design decisions
5. **Tests** - Unit and integration tests

### Prerequisites

- Zero Trust Auth service running (see [main documentation](../README.md))
- Appropriate SDK installed (see [SDK documentation](../sdk/))
- Framework-specific prerequisites (detailed in each example)

### Quick Start

1. Choose your framework from the examples above
2. Navigate to the example directory
3. Follow the README.md instructions
4. Run the example locally
5. Adapt the code for your use case

### Example Structure

```
examples/
├── frontend/
│   ├── react-spa/
│   │   ├── README.md
│   │   ├── package.json
│   │   ├── src/
│   │   └── tests/
│   └── ...
├── backend/
│   ├── go-fiber/
│   │   ├── README.md
│   │   ├── go.mod
│   │   ├── main.go
│   │   └── tests/
│   └── ...
└── ...
```

## Contributing

To add a new integration example:

1. Create a new directory under the appropriate category
2. Include a comprehensive README.md
3. Provide complete, working source code
4. Add configuration examples
5. Include tests where applicable
6. Update this main README.md

## Support

For questions about specific integrations:

1. Check the example's README.md
2. Review the [SDK documentation](../sdk/)
3. Consult the [main documentation](../README.md)
4. Open an issue on the project repository

## License

All examples are provided under the same license as the main project.