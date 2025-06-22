# Production Secrets Management

> **IMPORTANT**: This directory should NEVER contain actual secrets  
> **Purpose**: Document secret management patterns and templates only

## 🔒 **Secret Management Strategy**

### **Secret Storage Solutions**

1. **AWS Secrets Manager** (Recommended for AWS deployments)
2. **HashiCorp Vault** (Recommended for multi-cloud)
3. **Kubernetes Secrets** (With encryption at rest)
4. **External Secrets Operator** (GitOps friendly)

### **Required Secrets**

#### **Keycloak Secrets**
```yaml
# keycloak-secrets.yaml (TEMPLATE ONLY)
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-secrets
  namespace: zero-trust
type: Opaque
stringData:
  KEYCLOAK_ADMIN: "${KEYCLOAK_ADMIN}"
  KEYCLOAK_ADMIN_PASSWORD: "${KEYCLOAK_ADMIN_PASSWORD}"
  DB_PASSWORD: "${KEYCLOAK_DB_PASSWORD}"
  CLIENT_SECRET: "${KEYCLOAK_CLIENT_SECRET}"
```

#### **OPA Secrets**
```yaml
# opa-secrets.yaml (TEMPLATE ONLY)
apiVersion: v1
kind: Secret
metadata:
  name: opa-secrets
  namespace: zero-trust
type: Opaque
stringData:
  OPA_DB_PASSWORD: "${OPA_DB_PASSWORD}"
  BUNDLE_SERVICE_TOKEN: "${OPA_BUNDLE_TOKEN}"
```

#### **SPIRE Secrets**
```yaml
# spire-secrets.yaml (TEMPLATE ONLY)
apiVersion: v1
kind: Secret
metadata:
  name: spire-secrets
  namespace: zero-trust
type: Opaque
data:
  # Base64 encoded certificates
  ca-cert.pem: "${SPIRE_CA_CERT_B64}"
  ca-key.pem: "${SPIRE_CA_KEY_B64}"
```

### **Secret Rotation Policy**

| Secret Type | Rotation Frequency | Method |
|-------------|-------------------|---------|
| Admin Passwords | 90 days | Automated via Vault |
| Client Secrets | 180 days | Manual with zero downtime |
| Database Passwords | 90 days | Automated with connection pooling |
| JWT Signing Keys | 365 days | Key rotation with overlap |
| TLS Certificates | 90 days | Cert-manager automation |

## 🔧 **Production Configuration**

### **Environment-Specific Configs**

```bash
# Production environment variables (TEMPLATE)
# File: .env.production.template

# Keycloak Configuration
KEYCLOAK_URL=https://auth.yourdomain.com
KEYCLOAK_REALM=zero-trust-prod
KEYCLOAK_CLIENT_ID=zero-trust-app
KEYCLOAK_CLIENT_SECRET=<from-secrets-manager>

# OPA Configuration  
OPA_URL=https://opa.yourdomain.com
OPA_BUNDLE_URL=https://bundles.yourdomain.com/production
OPA_DECISION_LOG_ENABLED=true

# SPIRE Configuration
SPIRE_TRUST_DOMAIN=prod.yourdomain.com
SPIRE_SERVER_ADDRESS=spire-server.zero-trust.svc.cluster.local:8081

# Database Configuration
DATABASE_URL=postgres://app:<password>@db.yourdomain.com:5432/zerotrust?sslmode=require
REDIS_URL=rediss://:<password>@redis.yourdomain.com:6379/0

# Monitoring
PROMETHEUS_URL=http://prometheus.monitoring.svc.cluster.local:9090
GRAFANA_URL=https://grafana.yourdomain.com

# Feature Flags
ENABLE_DEVICE_ATTESTATION=true
ENABLE_COMPLIANCE_MODE=true
ENABLE_AUDIT_LOGGING=true
TRUST_LEVEL_ENFORCEMENT=strict
```

### **Security Hardening Checklist**

- [ ] All secrets stored in external secret management system
- [ ] TLS enabled for all service communication
- [ ] Network policies restricting pod-to-pod communication
- [ ] RBAC policies limiting service account permissions
- [ ] Pod security policies enforcing security standards
- [ ] Image scanning for all container images
- [ ] Admission controllers for policy enforcement
- [ ] Audit logging enabled for all API calls

### **Secret Generation Scripts**

```bash
#!/bin/bash
# generate-secrets.sh - Generate secure secrets

# Generate secure passwords
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Generate JWT signing key
generate_jwt_key() {
    openssl rand -base64 64
}

# Generate client secret
generate_client_secret() {
    openssl rand -hex 32
}

echo "Generating production secrets..."
echo "KEYCLOAK_ADMIN_PASSWORD=$(generate_password)"
echo "KEYCLOAK_DB_PASSWORD=$(generate_password)"
echo "KEYCLOAK_CLIENT_SECRET=$(generate_client_secret)"
echo "OPA_DB_PASSWORD=$(generate_password)"
echo "JWT_SIGNING_KEY=$(generate_jwt_key)"
```

## 🚨 **Security Best Practices**

1. **Never commit secrets to Git**
   - Use .gitignore for all secret files
   - Scan commits with git-secrets

2. **Use least privilege principle**
   - Each service has its own credentials
   - Minimal permissions for each service account

3. **Enable secret rotation**
   - Automated rotation where possible
   - Zero-downtime rotation procedures

4. **Audit secret access**
   - Log all secret retrievals
   - Alert on suspicious access patterns

5. **Encrypt secrets at rest**
   - Use KMS for encryption keys
   - Enable etcd encryption in Kubernetes

## 📋 **Secret Management Procedures**

### **Initial Setup**
1. Create secrets in external secret manager
2. Configure External Secrets Operator
3. Validate secret synchronization
4. Test application with production secrets

### **Secret Rotation**
1. Generate new secret value
2. Update in secret manager
3. Trigger rolling deployment
4. Validate services using new secret
5. Revoke old secret after grace period

### **Emergency Procedures**
1. Immediate secret rotation if compromised
2. Audit logs for unauthorized access
3. Update all dependent services
4. Security incident report

## 🔍 **Validation Commands**

```bash
# Verify secret encryption
kubectl get secret -n zero-trust keycloak-secrets -o yaml | grep -v "data:"

# Check External Secrets Operator sync
kubectl get externalsecrets -n zero-trust

# Validate secret permissions
kubectl auth can-i get secrets -n zero-trust --as=system:serviceaccount:zero-trust:app-service

# Test secret rotation
./scripts/rotate-secret.sh keycloak-client-secret
```

Remember: This directory contains only templates and documentation. Actual secrets must be stored in your chosen secret management system.