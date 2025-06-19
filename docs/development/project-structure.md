# Project Structure (2025)

```
root-zamaz/
├── api/                    # API definitions and contracts
├── bin/                    # Compiled binaries
├── charts/                 # Helm charts
│   ├── istio-mesh/        # Service mesh configurations
│   ├── observability/     # Monitoring stack
│   ├── security-policies/ # Security configurations
│   ├── spire-integration/ # SPIRE authentication
│   └── zamaz/            # Main application chart
├── cmd/                   # Application entrypoints
│   ├── server/           # Main server
│   ├── cli/              # CLI tools
│   └── dboptimize/       # Database tools
├── configs/              # Configuration files
│   ├── development/     # Development environment
│   ├── staging/        # Staging environment
│   └── production/     # Production environment
├── deployments/         # Deployment configurations
│   ├── kubernetes/     # Kubernetes manifests
│   │   ├── base/      # Base configurations
│   │   ├── overlays/  # Environment overlays
│   │   └── policies/  # Security policies
│   └── terraform/     # Infrastructure as code
├── docs/              # Documentation
│   ├── api/          # API documentation
│   ├── architecture/ # System design
│   ├── deployment/   # Deployment guides
│   ├── development/  # Development guides
│   ├── operations/   # Runbooks and procedures
│   ├── reference/    # Technical reference
│   └── security/     # Security guidelines
├── frontend/         # Frontend application
├── logs/            # Application logs
│   ├── auth/        # Authentication logs
│   ├── server/      # Server logs
│   └── frontend/    # Frontend logs
├── observability/   # Observability stack
│   ├── grafana/    # Dashboards
│   ├── prometheus/ # Metrics
│   └── jaeger/     # Tracing
├── pkg/            # Internal packages
├── scripts/        # Automation scripts
├── test-results/   # Test outputs
│   ├── unit/      # Unit test results
│   ├── e2e/       # End-to-end test results
│   └── integration/ # Integration test results
└── tests/          # Test suites
    ├── e2e/        # End-to-end tests
    ├── integration/ # Integration tests
    └── unit/       # Unit tests

# Key Files
├── .gitignore              # Git ignore patterns
├── README.md              # Project overview
├── Makefile              # Build automation
├── go.mod                # Go dependencies
└── package.json          # Node.js dependencies
```

## Structure Rationale

1. **Clear Separation of Concerns**
   - Each directory has a single responsibility
   - Environment-specific configs are isolated
   - Clear distinction between application and infrastructure code

2. **GitOps Ready**
   - Kubernetes manifests organized for Kustomize
   - Environment-specific overlays
   - Clear separation of base and environment configs

3. **Developer Friendly**
   - Documentation organized by domain
   - Clear build and test organization
   - Consistent logging structure

4. **Security First**
   - Dedicated security documentation
   - Clear policy management
   - Separate security configurations

5. **Observable**
   - Centralized observability configuration
   - Structured logging
   - Organized dashboards and alerts

## Maintenance Guidelines

1. **Documentation**
   - Keep README.md up to date
   - Document all new features
   - Update architecture diagrams

2. **Configuration**
   - Use environment overlays
   - Keep secrets in Vault
   - Document config changes

3. **Testing**
   - Maintain test organization
   - Keep coverage high
   - Regular test maintenance

4. **Security**
   - Regular policy updates
   - Security scan reports
   - Dependency updates

5. **Observability**
   - Update dashboards
   - Maintain alerts
   - Review logging
