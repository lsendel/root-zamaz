# GitOps Quick Start Guide

## Prerequisites
- Kubernetes cluster access
- ArgoCD CLI installed
- Helm v3+
- kubectl

## Initial Setup

1. **Deploy ArgoCD**
```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

2. **Configure Git Repository**
- Add your repository to ArgoCD
- Configure access credentials
- Set up webhook notifications

3. **Deploy Application**
```bash
# Apply the ArgoCD application
kubectl apply -f deployments/kubernetes/argocd/application.yaml

# Verify application sync
argocd app sync zamaz
```

## Common Operations

### Deploying Changes
1. Make changes to your code/configuration
2. Push to the Git repository
3. ArgoCD will automatically sync changes

### Monitoring Deployments
```bash
# Check deployment status
./scripts/validate-gitops.sh

# Monitor health metrics
./scripts/pre-deployment-check.sh
```

### Handling Incidents
```bash
# Run incident response script
./scripts/incident-response.sh production
```

## Environment Management

### Staging Deployment
```bash
argocd app create zamaz-staging \
  --dest-namespace zamaz-staging \
  --dest-server https://kubernetes.default.svc \
  --path charts/zamaz \
  --values values-staging.yaml
```

### Production Deployment
```bash
# Run pre-deployment checks
./scripts/pre-deployment-check.sh production

# Deploy to production
argocd app sync zamaz-production
```

## Monitoring & Alerts

### Access Dashboards
- Grafana: https://grafana.your-domain.com
- Prometheus: https://prometheus.your-domain.com
- ArgoCD: https://argocd.your-domain.com

### Common Metrics
- Application success rate
- Latency percentiles
- Resource utilization
- Cost optimization metrics

## Troubleshooting

### Common Issues

1. **Sync Failures**
```bash
# Check sync status
argocd app get zamaz-production --refresh

# Force sync if needed
argocd app sync zamaz-production --force
```

2. **Health Check Failures**
```bash
# Run health validation
./scripts/validate-gitops.sh

# Check application logs
kubectl logs -n zamaz-production -l app=zamaz
```

3. **Performance Issues**
- Check Grafana dashboards for anomalies
- Review resource utilization
- Verify autoscaling behavior

### Recovery Procedures

1. **Quick Rollback**
```bash
# Automatic rollback
./scripts/incident-response.sh production

# Manual rollback if needed
argocd app rollback zamaz-production
```

2. **Data Recovery**
```bash
# List available backups
velero get backup

# Restore from backup
velero restore create --from-backup backup-name
```

## Best Practices

1. **Change Management**
- Always use Git for changes
- Follow progressive delivery pattern
- Validate changes in staging first

2. **Monitoring**
- Regularly review SLO dashboards
- Keep alert thresholds updated
- Monitor cost optimization metrics

3. **Security**
- Rotate secrets regularly
- Review network policies
- Keep dependencies updated

## Support

For issues or questions:
- Slack: #platform-team
- Email: platform-support@your-company.com
- On-call: Use PagerDuty rotation
