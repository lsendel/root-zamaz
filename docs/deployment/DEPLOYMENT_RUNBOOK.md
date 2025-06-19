# Deployment Runbook

## Pre-Deployment Checklist

### Code Quality and Testing
- [ ] All tests passing (unit, integration, e2e)
- [ ] Code coverage meets minimum threshold (>80%)
- [ ] No critical or high security vulnerabilities
- [ ] Static code analysis passes
- [ ] Dependencies are up to date

### Infrastructure Readiness
- [ ] ArgoCD is operational
- [ ] Prometheus and Grafana are functioning
- [ ] Vault is accessible
- [ ] Required secrets are configured
- [ ] Cluster has sufficient resources

## Deployment Process

### 1. Staging Deployment
```bash
# Deployment is automated via GitHub Actions but can be triggered manually:
argocd app sync zamaz-staging
```

#### Monitoring Deployment
1. Check ArgoCD UI for sync status
2. Monitor canary metrics in Grafana dashboard
3. Verify endpoints:
   - /health/live
   - /health/ready
   - /metrics

#### Verification Steps
1. Check pod status and logs
2. Verify metrics in Prometheus
3. Run smoke tests
4. Check error rates in Grafana

### 2. Production Deployment

#### Pre-Production Checks
- [ ] Staging deployment successful for >24 hours
- [ ] No open critical issues
- [ ] All security scans passed
- [ ] Load testing completed
- [ ] Rollback plan reviewed

#### Deploy to Production
```bash
# Automated via GitHub Actions with manual approval
argocd app sync zamaz-production
```

#### Production Verification
1. Monitor canary deployment metrics
2. Check error rates and latency
3. Verify all health endpoints
4. Monitor business metrics

## Rollback Procedures

### Automatic Rollbacks
The system will automatically rollback if:
- Error rate exceeds 5% during canary
- P99 latency exceeds 500ms
- Health checks fail consistently

### Manual Rollback
```bash
# Revert to previous version
argocd app rollback zamaz-production
```

## Monitoring and Alerts

### Key Metrics to Monitor
- Request success rate
- Latency (p50, p90, p99)
- Error rates by type
- Resource utilization
- Authentication success/failure rates

### Alert Response
1. Check Grafana dashboards
2. Review application logs
3. Analyze error patterns
4. Escalate if needed per severity

## Troubleshooting Guide

### Common Issues

#### High Error Rate
1. Check application logs
2. Verify external dependencies
3. Review recent changes
4. Check resource utilization

#### Performance Issues
1. Monitor resource usage
2. Check database performance
3. Review network metrics
4. Analyze trace data

#### Authentication Failures
1. Verify Vault connectivity
2. Check certificate validity
3. Review auth service logs
4. Validate RBAC configuration

## Disaster Recovery

### Database Recovery
1. Stop application pods
2. Restore from backup
3. Verify data integrity
4. Restart application

### Certificate Rotation
1. Generate new certificates
2. Update Vault secrets
3. Rotate pods to pick up new certs

### Complete Service Recovery
1. Identify failure point
2. Restore from last known good state
3. Verify system integrity
4. Update documentation with lessons learned
