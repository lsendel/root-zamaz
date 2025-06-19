# CI/CD Strategy for Zero Trust Authentication MVP

## Overview

This document outlines the comprehensive CI/CD strategy for deploying the Zero Trust Authentication MVP across multiple environments with a focus on security, reliability, and scalability.

## Table of Contents
1. [Environment Strategy](#environment-strategy)
2. [GitOps Workflow](#gitops-workflow)
3. [Pipeline Architecture](#pipeline-architecture)
4. [Security & Compliance](#security--compliance)
5. [Multi-Cloud Strategy](#multi-cloud-strategy)
6. [Deployment Patterns](#deployment-patterns)
7. [Monitoring & Observability](#monitoring--observability)
8. [Disaster Recovery](#disaster-recovery)

## Environment Strategy

### Environment Topology
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ Development │───▶│   Testing   │───▶│   Staging   │───▶│ Pre-Production│───▶│ Production  │
│   (Local)   │    │ (Feature)   │    │(Integration)│    │  (Mirror)   │    │ (Multi-AZ)  │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                    │                  │                  │                  │
      ▼                    ▼                  ▼                  ▼                  ▼
  Single Node         K8s Cluster        K8s Cluster       K8s Cluster        Multi-Cluster
 Docker Compose      (Single Region)    (Single Region)   (Production-like)   (Multi-Region)
```

### Environment Characteristics

#### Development Environment
- **Purpose**: Local development and unit testing
- **Infrastructure**: Docker Compose on developer machines
- **Data**: Synthetic test data
- **Deployment**: Manual via `make dev-up`
- **Network**: Isolated local network

#### Testing Environment  
- **Purpose**: Feature testing and integration tests
- **Infrastructure**: Single-node Kubernetes cluster
- **Data**: Anonymized production data subset
- **Deployment**: Automated on feature branch merge
- **Network**: Isolated VPC with limited external access

#### Staging Environment
- **Purpose**: End-to-end testing and QA validation
- **Infrastructure**: 3-node Kubernetes cluster
- **Data**: Production-like data (anonymized)
- **Deployment**: Automated on main branch merge
- **Network**: Isolated VPC with controlled external access

#### Pre-Production Environment
- **Purpose**: Final validation and load testing
- **Infrastructure**: Production-mirror cluster
- **Data**: Production data replica (encrypted)
- **Deployment**: Manual promotion from staging
- **Network**: Production-like network topology

#### Production Environment
- **Purpose**: Live customer traffic
- **Infrastructure**: Multi-cluster, multi-region setup
- **Data**: Live production data
- **Deployment**: Blue/Green or Canary deployment
- **Network**: Full production network with security controls

### Environment Configuration

#### Network Isolation Strategy
```yaml
# Network segmentation per environment
Development:
  CIDR: 10.0.0.0/16
  Internet: Direct access
  
Testing:
  CIDR: 10.1.0.0/16
  Internet: Proxy only
  
Staging:
  CIDR: 10.2.0.0/16
  Internet: Limited access
  
Pre-Production:
  CIDR: 10.3.0.0/16
  Internet: Production-like restrictions
  
Production:
  CIDR: 10.10.0.0/16
  Internet: Full security controls
```

## GitOps Workflow

### Repository Structure
```
zamaz-platform/
├── applications/
│   ├── zamaz-api/
│   │   ├── src/
│   │   ├── Dockerfile
│   │   └── .github/workflows/
│   └── zamaz-frontend/
├── infrastructure/
│   ├── terraform/
│   │   ├── aws/
│   │   ├── gcp/
│   │   └── azure/
│   └── helm-charts/
├── gitops-config/
│   ├── environments/
│   │   ├── development/
│   │   ├── testing/
│   │   ├── staging/
│   │   ├── pre-production/
│   │   └── production/
│   └── applications/
└── security/
    ├── policies/
    ├── rbac/
    └── network-policies/
```

### Branch Strategy
```
main (production)
├── develop (staging)
│   ├── feature/auth-enhancement
│   ├── feature/new-middleware
│   └── hotfix/security-patch
└── release/v1.2.0 (pre-production)
```

### GitOps Flow with ArgoCD
```yaml
# argocd-projects.yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: zamaz-platform
  namespace: argocd
spec:
  description: Zamaz Platform Applications
  sourceRepos:
  - 'https://github.com/company/zamaz-platform'
  - 'https://github.com/company/zamaz-config'
  destinations:
  - namespace: 'zamaz-*'
    server: '*'
  clusterResourceWhitelist:
  - group: ''
    kind: Namespace
  - group: rbac.authorization.k8s.io
    kind: ClusterRole
  roles:
  - name: developers
    description: Developer access
    policies:
    - p, proj:zamaz-platform:developers, applications, get, zamaz-platform/*, allow
    - p, proj:zamaz-platform:developers, applications, sync, zamaz-platform/zamaz-dev, allow
  - name: sre-team
    description: SRE team access
    policies:
    - p, proj:zamaz-platform:sre-team, applications, *, zamaz-platform/*, allow
    - p, proj:zamaz-platform:sre-team, repositories, *, *, allow
```

## Pipeline Architecture

### GitHub Actions Pipeline
```yaml
# .github/workflows/main.yml
name: Zamaz Platform CI/CD

on:
  push:
    branches: [main, develop]
    tags: ['v*']
  pull_request:
    branches: [main, develop]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        format: 'sarif'
        output: 'trivy-results.sarif'
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go-version: [1.21]
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-go@v4
      with:
        go-version: ${{ matrix.go-version }}
    - name: Cache Go modules
      uses: actions/cache@v3
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}
    - name: Run tests with coverage
      run: |
        go test -race -coverprofile=coverage.out -covermode=atomic ./...
        go tool cover -html=coverage.out -o coverage.html
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out

  build-and-push:
    needs: [security-scan, test]
    runs-on: ubuntu-latest
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
    steps:
    - uses: actions/checkout@v4
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v5
      with:
        images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
        tags: |
          type=ref,event=branch
          type=ref,event=pr
          type=semver,pattern={{version}}
          type=semver,pattern={{major}}.{{minor}}
          type=sha,prefix={{branch}}-
    - name: Build and push Docker image
      id: build
      uses: docker/build-push-action@v5
      with:
        context: .
        platforms: linux/amd64,linux/arm64
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max

  deploy-development:
    if: github.ref == 'refs/heads/develop'
    needs: build-and-push
    runs-on: ubuntu-latest
    environment: development
    steps:
    - uses: actions/checkout@v4
      with:
        repository: company/zamaz-config
        token: ${{ secrets.GITOPS_TOKEN }}
        path: config
    - name: Update development config
      run: |
        cd config/environments/development
        kustomize edit set image zamaz=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ needs.build-and-push.outputs.image-digest }}
        git config user.name "GitHub Actions"
        git config user.email "actions@github.com"
        git add .
        git commit -m "Update development image to ${{ github.sha }}"
        git push

  deploy-staging:
    if: github.ref == 'refs/heads/main'
    needs: build-and-push
    runs-on: ubuntu-latest
    environment: staging
    steps:
    - uses: actions/checkout@v4
      with:
        repository: company/zamaz-config
        token: ${{ secrets.GITOPS_TOKEN }}
        path: config
    - name: Update staging config
      run: |
        cd config/environments/staging
        kustomize edit set image zamaz=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ needs.build-and-push.outputs.image-digest }}
        git config user.name "GitHub Actions"
        git config user.email "actions@github.com"
        git add .
        git commit -m "Update staging image to ${{ github.sha }}"
        git push

  promote-to-production:
    if: startsWith(github.ref, 'refs/tags/v')
    needs: build-and-push
    runs-on: ubuntu-latest
    environment: production
    steps:
    - name: Slack notification
      uses: 8398a7/action-slack@v3
      with:
        status: custom
        custom_payload: |
          {
            text: "Production deployment initiated for Zamaz ${{ github.ref_name }}",
            attachments: [{
              color: 'warning',
              fields: [{
                title: 'Environment',
                value: 'Production',
                short: true
              }, {
                title: 'Version',
                value: '${{ github.ref_name }}',
                short: true
              }]
            }]
          }
      env:
        SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
    - uses: actions/checkout@v4
      with:
        repository: company/zamaz-config
        token: ${{ secrets.GITOPS_TOKEN }}
        path: config
    - name: Create production PR
      run: |
        cd config
        git checkout -b production-release-${{ github.ref_name }}
        cd environments/production
        kustomize edit set image zamaz=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ needs.build-and-push.outputs.image-digest }}
        git config user.name "GitHub Actions"
        git config user.email "actions@github.com"
        git add .
        git commit -m "Production release ${{ github.ref_name }}"
        git push origin production-release-${{ github.ref_name }}
        gh pr create --title "Production Release ${{ github.ref_name }}" \
          --body "Automated production release for version ${{ github.ref_name }}" \
          --head production-release-${{ github.ref_name }} \
          --base main
      env:
        GH_TOKEN: ${{ secrets.GITOPS_TOKEN }}
```

### Jenkins Pipeline (Alternative)
```groovy
// Jenkinsfile
pipeline {
    agent {
        kubernetes {
            yaml """
                apiVersion: v1
                kind: Pod
                spec:
                  containers:
                  - name: go
                    image: golang:1.21
                    command: ['sleep']
                    args: ['infinity']
                  - name: docker
                    image: docker:24-dind
                    securityContext:
                      privileged: true
                  - name: kubectl
                    image: bitnami/kubectl:latest
                    command: ['sleep']
                    args: ['infinity']
            """
        }
    }
    
    environment {
        REGISTRY = 'your-registry.com'
        IMAGE_NAME = 'zamaz'
        KUBECONFIG = credentials('kubeconfig')
    }
    
    stages {
        stage('Code Quality') {
            parallel {
                stage('Security Scan') {
                    steps {
                        container('go') {
                            sh 'go install github.com/securecodewarrior/github-action-add-sarif@latest'
                            sh 'gosec -fmt sarif -out results.sarif ./...'
                            publishHTML([
                                allowMissing: false,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: '.',
                                reportFiles: 'results.sarif',
                                reportName: 'Security Scan Report'
                            ])
                        }
                    }
                }
                
                stage('Unit Tests') {
                    steps {
                        container('go') {
                            sh 'go test -race -coverprofile=coverage.out ./...'
                            sh 'go tool cover -html=coverage.out -o coverage.html'
                            publishHTML([
                                allowMissing: false,
                                alwaysLinkToLastBuild: true,
                                keepAll: true,
                                reportDir: '.',
                                reportFiles: 'coverage.html',
                                reportName: 'Coverage Report'
                            ])
                        }
                    }
                }
                
                stage('Lint') {
                    steps {
                        container('go') {
                            sh 'go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest'
                            sh 'golangci-lint run --out-format checkstyle > golangci-lint.xml'
                            recordIssues(
                                enabledForFailure: true,
                                tools: [checkStyle(pattern: 'golangci-lint.xml')]
                            )
                        }
                    }
                }
            }
        }
        
        stage('Build') {
            steps {
                container('docker') {
                    script {
                        def image = docker.build("${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}")
                        docker.withRegistry("https://${REGISTRY}", 'registry-credentials') {
                            image.push()
                            image.push('latest')
                        }
                    }
                }
            }
        }
        
        stage('Deploy to Development') {
            when {
                branch 'develop'
            }
            steps {
                container('kubectl') {
                    sh """
                        kubectl set image deployment/zamaz-api zamaz=${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} -n zamaz-dev
                        kubectl rollout status deployment/zamaz-api -n zamaz-dev --timeout=300s
                    """
                }
            }
        }
        
        stage('Integration Tests') {
            when {
                branch 'develop'
            }
            steps {
                container('go') {
                    sh 'go test -tags=integration ./tests/integration/...'
                }
            }
        }
        
        stage('Deploy to Staging') {
            when {
                branch 'main'
            }
            steps {
                input message: 'Deploy to staging?', ok: 'Deploy'
                container('kubectl') {
                    sh """
                        kubectl set image deployment/zamaz-api zamaz=${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} -n zamaz-staging
                        kubectl rollout status deployment/zamaz-api -n zamaz-staging --timeout=300s
                    """
                }
            }
        }
        
        stage('Load Testing') {
            when {
                branch 'main'
            }
            steps {
                container('kubectl') {
                    sh """
                        kubectl create job load-test-${BUILD_NUMBER} --from=cronjob/zamaz-load-test -n zamaz-staging
                        kubectl wait --for=condition=complete job/load-test-${BUILD_NUMBER} -n zamaz-staging --timeout=600s
                    """
                }
            }
        }
        
        stage('Production Deployment') {
            when {
                buildingTag()
            }
            steps {
                input message: 'Deploy to production?', ok: 'Deploy', submitterParameter: 'APPROVER'
                script {
                    // Blue/Green deployment
                    container('kubectl') {
                        sh """
                            # Deploy to green environment
                            kubectl set image deployment/zamaz-api-green zamaz=${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} -n zamaz-prod
                            kubectl rollout status deployment/zamaz-api-green -n zamaz-prod --timeout=300s
                            
                            # Health check
                            kubectl exec deployment/zamaz-api-green -n zamaz-prod -- curl -f http://localhost:8080/health
                            
                            # Switch traffic
                            kubectl patch service zamaz-api -n zamaz-prod -p '{"spec":{"selector":{"version":"green"}}}'
                            
                            # Wait and monitor
                            sleep 300
                            
                            # Update blue to new version
                            kubectl set image deployment/zamaz-api-blue zamaz=${REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} -n zamaz-prod
                        """
                    }
                }
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
        success {
            slackSend(
                channel: '#deployments',
                color: 'good',
                message: "✅ Zamaz deployment successful: ${env.JOB_NAME} - ${env.BUILD_NUMBER}"
            )
        }
        failure {
            slackSend(
                channel: '#deployments',
                color: 'danger',
                message: "❌ Zamaz deployment failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}"
            )
        }
    }
}
```

## Security & Compliance

### Security Pipeline Integration
```yaml
# security-pipeline.yml
name: Security Pipeline

on:
  pull_request:
    branches: [main, develop]
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    - name: GitLeaks scan
      uses: zricethezav/gitleaks-action@v1.2.0
      with:
        config-path: .gitleaks.toml

  dependency-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Go vulnerability scan
      run: |
        go install golang.org/x/vuln/cmd/govulncheck@latest
        govulncheck ./...

  container-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Build image for scanning
      run: docker build -t zamaz:scan .
    - name: Trivy container scan
      uses: aquasecurity/trivy-action@master
      with:
        image-ref: 'zamaz:scan'
        format: 'table'
        exit-code: '1'
        severity: 'CRITICAL,HIGH'

  infrastructure-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Checkov scan
      uses: bridgecrewio/checkov-action@master
      with:
        directory: infrastructure/
        framework: terraform,kubernetes
        output_format: sarif
        output_file_path: checkov.sarif

  policy-validation:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: OPA policy validation
      run: |
        curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
        chmod +x opa
        ./opa test security/policies/
```

### Compliance Automation
```yaml
# compliance-check.yml
apiVersion: v1
kind: ConfigMap
metadata:
  name: compliance-policies
  namespace: zamaz-compliance
data:
  pod-security-standards.rego: |
    package kubernetes.admission
    
    import data.kubernetes.pods
    
    deny[msg] {
      pod := pods[_]
      pod.spec.securityContext.runAsRoot == true
      msg := sprintf("Pod %s runs as root", [pod.metadata.name])
    }
    
    deny[msg] {
      pod := pods[_]
      container := pod.spec.containers[_]
      not container.securityContext.readOnlyRootFilesystem
      msg := sprintf("Container %s does not have read-only root filesystem", [container.name])
    }

  network-policies.rego: |
    package kubernetes.network
    
    required_network_policies := ["zamaz-api", "zamaz-frontend", "zamaz-database"]
    
    deny[msg] {
      namespace := input.review.object.metadata.namespace
      namespace == "zamaz-prod"
      policy := required_network_policies[_]
      not has_network_policy(policy)
      msg := sprintf("Missing required network policy: %s", [policy])
    }
```

## Multi-Cloud Strategy

### Cloud Provider Abstraction
```yaml
# terraform/modules/kubernetes-cluster/main.tf
variable "cloud_provider" {
  description = "Cloud provider (aws, gcp, azure)"
  type        = string
}

variable "cluster_config" {
  description = "Cluster configuration"
  type = object({
    name         = string
    region       = string
    node_count   = number
    machine_type = string
    disk_size    = number
  })
}

module "aws_cluster" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  source = "./aws-eks"
  
  cluster_name = var.cluster_config.name
  region       = var.cluster_config.region
  node_count   = var.cluster_config.node_count
  # ... other configurations
}

module "gcp_cluster" {
  count  = var.cloud_provider == "gcp" ? 1 : 0
  source = "./gcp-gke"
  
  cluster_name = var.cluster_config.name
  region       = var.cluster_config.region
  node_count   = var.cluster_config.node_count
  # ... other configurations
}

module "azure_cluster" {
  count  = var.cloud_provider == "azure" ? 1 : 0
  source = "./azure-aks"
  
  cluster_name = var.cluster_config.name
  region       = var.cluster_config.region
  node_count   = var.cluster_config.node_count
  # ... other configurations
}
```

### Cross-Cloud Deployment Pipeline
```yaml
# .github/workflows/multi-cloud-deploy.yml
name: Multi-Cloud Deployment

on:
  workflow_dispatch:
    inputs:
      target_clouds:
        description: 'Target clouds (comma-separated: aws,gcp,azure)'
        required: true
        default: 'aws,gcp'
      environment:
        description: 'Environment'
        required: true
        default: 'staging'
        type: choice
        options:
        - staging
        - production

jobs:
  deploy:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        cloud: ${{ fromJson(format('["{0}"]', join(fromJson(format('["%s"]', replace(github.event.inputs.target_clouds, ',', '","'))), '","'))) }}
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup cloud credentials
      run: |
        case "${{ matrix.cloud }}" in
          aws)
            echo "Setting up AWS credentials"
            aws configure set aws_access_key_id ${{ secrets.AWS_ACCESS_KEY_ID }}
            aws configure set aws_secret_access_key ${{ secrets.AWS_SECRET_ACCESS_KEY }}
            aws configure set region us-west-2
            ;;
          gcp)
            echo "Setting up GCP credentials"
            echo '${{ secrets.GCP_SA_KEY }}' | base64 -d > gcp-key.json
            gcloud auth activate-service-account --key-file=gcp-key.json
            gcloud config set project ${{ secrets.GCP_PROJECT_ID }}
            ;;
          azure)
            echo "Setting up Azure credentials"
            az login --service-principal -u ${{ secrets.AZURE_CLIENT_ID }} -p ${{ secrets.AZURE_CLIENT_SECRET }} --tenant ${{ secrets.AZURE_TENANT_ID }}
            ;;
        esac

    - name: Deploy to ${{ matrix.cloud }}
      run: |
        cd infrastructure/terraform/${{ matrix.cloud }}
        terraform init
        terraform workspace select ${{ github.event.inputs.environment }} || terraform workspace new ${{ github.event.inputs.environment }}
        terraform plan -var="environment=${{ github.event.inputs.environment }}"
        terraform apply -auto-approve -var="environment=${{ github.event.inputs.environment }}"
        
        # Get cluster credentials
        case "${{ matrix.cloud }}" in
          aws)
            aws eks update-kubeconfig --region us-west-2 --name zamaz-${{ github.event.inputs.environment }}
            ;;
          gcp)
            gcloud container clusters get-credentials zamaz-${{ github.event.inputs.environment }} --region us-central1
            ;;
          azure)
            az aks get-credentials --resource-group zamaz-${{ github.event.inputs.environment }} --name zamaz-${{ github.event.inputs.environment }}
            ;;
        esac
        
        # Deploy application
        helm upgrade --install zamaz ../../charts/zamaz \
          --namespace zamaz-${{ github.event.inputs.environment }} \
          --create-namespace \
          --values values-${{ github.event.inputs.environment }}.yaml \
          --values values-${{ matrix.cloud }}.yaml
```

## Deployment Patterns

### Blue/Green Deployment
```bash
#!/bin/bash
# scripts/blue-green-deploy.sh

set -e

NAMESPACE=${1:-zamaz-prod}
NEW_IMAGE=${2}
TIMEOUT=${3:-300}

echo "Starting Blue/Green deployment..."
echo "Namespace: $NAMESPACE"
echo "New Image: $NEW_IMAGE"

# Get current active version
CURRENT_VERSION=$(kubectl get service zamaz-api -n $NAMESPACE -o jsonpath='{.spec.selector.version}')
echo "Current active version: $CURRENT_VERSION"

# Determine target version
if [ "$CURRENT_VERSION" = "blue" ]; then
    TARGET_VERSION="green"
    STANDBY_VERSION="blue"
else
    TARGET_VERSION="blue"
    STANDBY_VERSION="green"
fi

echo "Deploying to: $TARGET_VERSION"

# Update target deployment
kubectl set image deployment/zamaz-api-$TARGET_VERSION \
    zamaz=$NEW_IMAGE \
    -n $NAMESPACE

# Wait for rollout
echo "Waiting for $TARGET_VERSION deployment to be ready..."
kubectl rollout status deployment/zamaz-api-$TARGET_VERSION \
    -n $NAMESPACE \
    --timeout=${TIMEOUT}s

# Health check
echo "Performing health check..."
kubectl exec deployment/zamaz-api-$TARGET_VERSION \
    -n $NAMESPACE \
    -- curl -f http://localhost:8080/health

# Switch traffic
echo "Switching traffic to $TARGET_VERSION..."
kubectl patch service zamaz-api \
    -n $NAMESPACE \
    -p "{\"spec\":{\"selector\":{\"version\":\"$TARGET_VERSION\"}}}"

# Monitor for 5 minutes
echo "Monitoring for 5 minutes..."
sleep 300

# Check error rate
ERROR_RATE=$(kubectl exec deployment/prometheus -n monitoring -- \
    promtool query instant \
    'rate(http_requests_total{job="zamaz-api",status=~"5.."}[5m]) / rate(http_requests_total{job="zamaz-api"}[5m]) * 100' \
    | grep -o '[0-9.]*' | head -1)

if (( $(echo "$ERROR_RATE > 1" | bc -l) )); then
    echo "Error rate too high ($ERROR_RATE%), rolling back..."
    kubectl patch service zamaz-api \
        -n $NAMESPACE \
        -p "{\"spec\":{\"selector\":{\"version\":\"$STANDBY_VERSION\"}}}"
    exit 1
fi

# Update standby to new version
echo "Updating standby deployment..."
kubectl set image deployment/zamaz-api-$STANDBY_VERSION \
    zamaz=$NEW_IMAGE \
    -n $NAMESPACE

echo "Blue/Green deployment completed successfully!"
```

### Canary Deployment with Flagger
```yaml
# flagger-canary.yaml
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: zamaz-api
  namespace: zamaz-prod
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: zamaz-api
  progressDeadlineSeconds: 60
  autoscalerRef:
    apiVersion: autoscaling/v2
    kind: HorizontalPodAutoscaler
    name: zamaz-api
  service:
    port: 8080
    targetPort: 8080
    gateways:
    - public-gateway.istio-system.svc.cluster.local
    hosts:
    - api.zamaz.com
  analysis:
    interval: 1m
    threshold: 10
    maxWeight: 50
    stepWeight: 5
    metrics:
    - name: request-success-rate
      thresholdRange:
        min: 99
      interval: 1m
    - name: request-duration
      thresholdRange:
        max: 500
      interval: 30s
    - name: cpu-usage
      thresholdRange:
        max: 80
      interval: 1m
    webhooks:
    - name: acceptance-test
      type: pre-rollout
      url: http://zamaz-acceptance-tests.zamaz-prod/
      timeout: 30s
      metadata:
        type: bash
        cmd: "curl -sd 'test' http://zamaz-api-canary:8080/health | grep -q 'healthy'"
    - name: load-test
      type: rollout
      url: http://zamaz-load-test.zamaz-prod/
      metadata:
        cmd: "hey -z 2m -q 10 -c 2 http://zamaz-api-canary.zamaz-prod:8080/health"
  alerts:
  - name: "Canary deployment failed"
    severity: error
    providerRef:
      name: slack
      namespace: flagger-system
```

## Monitoring & Observability

### Deployment Monitoring
```yaml
# monitoring/deployment-dashboard.json
{
  "dashboard": {
    "title": "Zamaz Deployment Monitoring",
    "panels": [
      {
        "title": "Deployment Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "increase(deployment_success_total{service=\"zamaz\"}[24h]) / increase(deployment_total{service=\"zamaz\"}[24h]) * 100",
            "legendFormat": "Success Rate %"
          }
        ]
      },
      {
        "title": "Deployment Duration",
        "type": "graph",
        "targets": [
          {
            "expr": "deployment_duration_seconds{service=\"zamaz\"}",
            "legendFormat": "{{environment}}"
          }
        ]
      },
      {
        "title": "Rollback Events",
        "type": "graph",
        "targets": [
          {
            "expr": "increase(deployment_rollback_total{service=\"zamaz\"}[1h])",
            "legendFormat": "{{environment}}"
          }
        ]
      }
    ]
  }
}
```

### Alert Rules for Deployments
```yaml
# monitoring/deployment-alerts.yaml
groups:
- name: deployment.rules
  rules:
  - alert: DeploymentFailed
    expr: increase(deployment_failed_total{service="zamaz"}[10m]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Zamaz deployment failed"
      description: "Deployment failed in {{ $labels.environment }}"

  - alert: HighRollbackRate
    expr: increase(deployment_rollback_total{service="zamaz"}[1h]) > 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High rollback rate detected"
      description: "More than 2 rollbacks in the last hour"

  - alert: DeploymentStuck
    expr: time() - deployment_started_timestamp{service="zamaz"} > 1800
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Deployment taking too long"
      description: "Deployment has been running for more than 30 minutes"
```

## Disaster Recovery

### Backup Strategy
```yaml
# backup/velero-backup.yaml
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: zamaz-daily-backup
  namespace: velero
spec:
  schedule: "0 1 * * *"
  template:
    includedNamespaces:
    - zamaz-prod
    - zamaz-staging
    excludedResources:
    - events
    - events.events.k8s.io
    storageLocation: aws-s3
    volumeSnapshotLocations:
    - aws-ebs
    ttl: 720h0m0s  # 30 days
    hooks:
      resources:
      - name: postgres-backup
        includedNamespaces:
        - zamaz-prod
        includedResources:
        - pods
        labelSelector:
          matchLabels:
            app: postgresql
        pre:
        - exec:
            container: postgresql
            command:
            - /bin/bash
            - -c
            - "pg_dump -h localhost -U zamaz zamaz > /tmp/backup.sql"
        post:
        - exec:
            container: postgresql
            command:
            - /bin/bash
            - -c
            - "rm -f /tmp/backup.sql"
```

### Multi-Region Disaster Recovery
```bash
#!/bin/bash
# scripts/disaster-recovery.sh

PRIMARY_REGION="us-west-2"
DR_REGION="us-east-1"
NAMESPACE="zamaz-prod"

echo "Initiating disaster recovery from $PRIMARY_REGION to $DR_REGION..."

# Switch kubectl context to DR region
kubectl config use-context zamaz-dr-cluster

# Restore from backup
velero restore create zamaz-dr-restore \
    --from-backup zamaz-daily-backup-$(date +%Y%m%d) \
    --namespace-mappings zamaz-prod:zamaz-prod-dr

# Wait for restore to complete
velero restore describe zamaz-dr-restore --details

# Update DNS to point to DR region
aws route53 change-resource-record-sets \
    --hosted-zone-id Z123456789 \
    --change-batch '{
        "Changes": [{
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": "api.zamaz.com",
                "Type": "CNAME",
                "TTL": 60,
                "ResourceRecords": [{"Value": "api-dr.zamaz.com"}]
            }
        }]
    }'

# Verify application health
kubectl exec deployment/zamaz-api -n zamaz-prod-dr -- curl -f http://localhost:8080/health

echo "Disaster recovery completed. Application is now running in $DR_REGION"
```

## Summary

This CI/CD strategy provides:

1. **Comprehensive Environment Management**: Clear progression from development to production
2. **Security-First Approach**: Integrated security scanning and compliance validation
3. **Multi-Cloud Flexibility**: Cloud-agnostic deployment with provider-specific optimizations
4. **Advanced Deployment Patterns**: Blue/Green and Canary deployments for zero-downtime releases
5. **Robust Monitoring**: Full observability into deployment processes and application health
6. **Disaster Recovery**: Automated backup and recovery procedures

The strategy ensures reliable, secure, and scalable deployments while maintaining operational excellence across all environments and cloud providers.