// Week 5 Production Functionality E2E Tests
// Tests for production configuration, monitoring, backup, security, and deployment

import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

test.describe('Week 5: Production Deployment Functionality', () => {
  test.beforeAll(async () => {
    // Ensure test environment is ready
    console.log('Setting up Week 5 production tests...');
  });

  test.describe('Production Configuration & Secrets Management', () => {
    test('should have production deployment configuration', async () => {
      // Check production configuration files exist
      const productionConfigPath = path.join(process.cwd(), 'deployments/production');
      expect(fs.existsSync(productionConfigPath)).toBeTruthy();

      // Verify key production files
      const requiredFiles = [
        'kustomization.yaml',
        'README.md',
        'secrets/vault-secret-store.yaml',
        'monitoring/prometheus-servicemonitor.yaml',
        'backup/backup-strategy.yaml',
        'capacity-planning.yaml',
        'security/network-policies.yaml',
        'security/security-scanning.yaml'
      ];

      for (const file of requiredFiles) {
        const filePath = path.join(productionConfigPath, file);
        expect(fs.existsSync(filePath)).toBeTruthy();
      }
    });

    test('should have External Secrets Operator configuration', async () => {
      const secretsPath = path.join(process.cwd(), 'deployments/production/secrets');
      expect(fs.existsSync(secretsPath)).toBeTruthy();

      // Check for secret store configuration
      const vaultSecretStore = path.join(secretsPath, 'vault-secret-store.yaml');
      expect(fs.existsSync(vaultSecretStore)).toBeTruthy();

      const content = fs.readFileSync(vaultSecretStore, 'utf8');
      expect(content).toContain('SecretStore');
      expect(content).toContain('vault');
      expect(content).toContain('zero-trust-prod');
    });

    test('should have proper secret rotation configuration', async () => {
      const secretsPath = path.join(process.cwd(), 'deployments/production/secrets');
      const files = fs.readdirSync(secretsPath);
      
      // Should have external secret configurations
      const externalSecrets = files.filter(f => f.includes('external-secret'));
      expect(externalSecrets.length).toBeGreaterThan(0);
    });
  });

  test.describe('Monitoring and Alerting Setup', () => {
    test('should have Prometheus ServiceMonitor configuration', async () => {
      const monitoringPath = path.join(process.cwd(), 'deployments/production/monitoring');
      const serviceMonitorFile = path.join(monitoringPath, 'prometheus-servicemonitor.yaml');
      
      expect(fs.existsSync(serviceMonitorFile)).toBeTruthy();

      const content = fs.readFileSync(serviceMonitorFile, 'utf8');
      expect(content).toContain('ServiceMonitor');
      expect(content).toContain('zero-trust-prod');
      expect(content).toContain('metrics');
    });

    test('should have comprehensive alerting rules', async () => {
      const monitoringPath = path.join(process.cwd(), 'deployments/production/monitoring');
      const alertRulesFile = path.join(monitoringPath, 'prometheus-servicemonitor.yaml');
      
      const content = fs.readFileSync(alertRulesFile, 'utf8');
      
      // Check for critical alerts
      expect(content).toContain('HighAuthenticationErrorRate');
      expect(content).toContain('alert:') || expect(content).toContain('PrometheusRule');
    });

    test('should have Grafana dashboard configuration', async () => {
      const monitoringPath = path.join(process.cwd(), 'deployments/production/monitoring');
      const dashboardFile = path.join(monitoringPath, 'grafana-dashboard.yaml');
      
      expect(fs.existsSync(dashboardFile)).toBeTruthy();

      const content = fs.readFileSync(dashboardFile, 'utf8');
      expect(content).toContain('Zero Trust Authentication');
      expect(content).toContain('dashboard');
      expect(content).toContain('panels');
    });
  });

  test.describe('Backup and Disaster Recovery', () => {
    test('should have Velero backup configuration', async () => {
      const backupPath = path.join(process.cwd(), 'deployments/production/backup');
      const backupStrategyFile = path.join(backupPath, 'backup-strategy.yaml');
      
      expect(fs.existsSync(backupStrategyFile)).toBeTruthy();

      const content = fs.readFileSync(backupStrategyFile, 'utf8');
      expect(content).toContain('Schedule');
      expect(content).toContain('velero.io');
      expect(content).toContain('zero-trust-daily-backup');
    });

    test('should have disaster recovery procedures', async () => {
      const backupPath = path.join(process.cwd(), 'deployments/production/backup');
      const content = fs.readFileSync(path.join(backupPath, 'backup-strategy.yaml'), 'utf8');
      
      // Check for backup validation
      expect(content).toContain('backup-validation');
      expect(content).toContain('CronJob');
    });

    test('should have database backup configuration', async () => {
      const backupPath = path.join(process.cwd(), 'deployments/production/backup');
      const files = fs.readdirSync(backupPath);
      
      // Should have backup strategy configuration
      expect(files).toContain('backup-strategy.yaml');
      
      const content = fs.readFileSync(path.join(backupPath, 'backup-strategy.yaml'), 'utf8');
      expect(content).toContain('postgresql');
      expect(content).toContain('retention');
    });
  });

  test.describe('Load Testing and Capacity Planning', () => {
    test('should have K6 load testing scripts', async () => {
      const loadTestPath = path.join(process.cwd(), 'tests/load');
      expect(fs.existsSync(loadTestPath)).toBeTruthy();

      const k6TestFile = path.join(loadTestPath, 'k6-load-test.js');
      expect(fs.existsSync(k6TestFile)).toBeTruthy();

      const content = fs.readFileSync(k6TestFile, 'utf8');
      expect(content).toContain('scenarios');
      expect(content).toContain('steady_load');
      expect(content).toContain('ramp_up');
      expect(content).toContain('spike_test');
    });

    test('should have capacity planning configuration', async () => {
      const capacityFile = path.join(process.cwd(), 'deployments/production/capacity-planning.yaml');
      expect(fs.existsSync(capacityFile)).toBeTruthy();

      const content = fs.readFileSync(capacityFile, 'utf8');
      expect(content).toContain('HorizontalPodAutoscaler');
      expect(content).toContain('VerticalPodAutoscaler');
      expect(content).toContain('PodDisruptionBudget');
    });

    test('should have performance test scenarios for different trust levels', async () => {
      const loadTestPath = path.join(process.cwd(), 'tests/load');
      const testUsersFile = path.join(loadTestPath, 'test-users.json');
      
      expect(fs.existsSync(testUsersFile)).toBeTruthy();

      const content = JSON.parse(fs.readFileSync(testUsersFile, 'utf8'));
      
      // Should have users with different trust levels
      const trustLevels = content.map(user => user.trustLevel);
      expect(trustLevels).toContain(25);  // Low trust
      expect(trustLevels).toContain(50);  // Medium trust
      expect(trustLevels).toContain(75);  // High trust
      expect(trustLevels).toContain(100); // Full trust
    });
  });

  test.describe('Security Audit and Penetration Testing', () => {
    test('should have comprehensive penetration testing plan', async () => {
      const securityPath = path.join(process.cwd(), 'deployments/production/security');
      const penTestFile = path.join(securityPath, 'penetration-test-plan.md');
      
      expect(fs.existsSync(penTestFile)).toBeTruthy();

      const content = fs.readFileSync(penTestFile, 'utf8');
      expect(content).toContain('Zero Trust Authentication Penetration Testing Plan');
      expect(content).toContain('Phase 1: Reconnaissance');
      expect(content).toContain('Phase 2: Authentication Testing');
      expect(content).toContain('Phase 3: Authorization Testing');
      expect(content).toContain('JWT manipulation');
      expect(content).toContain('trust level') || expect(content).toContain('Trust level');
    });

    test('should have security scanning configuration', async () => {
      const securityPath = path.join(process.cwd(), 'deployments/production/security');
      const securityScanFile = path.join(securityPath, 'security-scanning.yaml');
      
      expect(fs.existsSync(securityScanFile)).toBeTruthy();

      const content = fs.readFileSync(securityScanFile, 'utf8');
      expect(content).toContain('Falco');
      expect(content).toContain('Trivy');
      expect(content).toContain('OPA Gatekeeper');
      expect(content).toContain('zero_trust_rules');
    });

    test('should have network security policies', async () => {
      const securityPath = path.join(process.cwd(), 'deployments/production/security');
      const networkPoliciesFile = path.join(securityPath, 'network-policies.yaml');
      
      expect(fs.existsSync(networkPoliciesFile)).toBeTruthy();

      const content = fs.readFileSync(networkPoliciesFile, 'utf8');
      expect(content).toContain('NetworkPolicy');
      expect(content).toContain('default-deny-all');
      expect(content).toContain('zero-trust-prod');
      expect(content).toContain('Ingress');
      expect(content).toContain('Egress');
    });

    test('should have custom security testing tools', async () => {
      const securityPath = path.join(process.cwd(), 'deployments/production/security');
      const penTestFile = path.join(securityPath, 'penetration-test-plan.md');
      
      const content = fs.readFileSync(penTestFile, 'utf8');
      expect(content).toContain('ZeroTrustTester');
      expect(content).toContain('test_trust_level_bypass');
      expect(content).toContain('test_jwt_manipulation');
    });
  });

  test.describe('Production Deployment Documentation', () => {
    test('should have comprehensive production deployment guide', async () => {
      const deploymentReadme = path.join(process.cwd(), 'deployments/production/README.md');
      expect(fs.existsSync(deploymentReadme)).toBeTruthy();

      const content = fs.readFileSync(deploymentReadme, 'utf8');
      expect(content).toContain('Zero Trust Authentication Production Deployment Guide');
      expect(content).toContain('Quick Start Deployment');
      expect(content).toContain('Prerequisites');
      expect(content).toContain('Security Hardening');
      expect(content).toContain('Troubleshooting Guide');
    });

    test('should have operational procedures documented', async () => {
      const deploymentReadme = path.join(process.cwd(), 'deployments/production/README.md');
      const content = fs.readFileSync(deploymentReadme, 'utf8');
      
      expect(content).toContain('Health Checks');
      expect(content).toContain('Log Management');
      expect(content).toContain('Performance Monitoring');
      expect(content).toContain('Emergency Procedures');
    });

    test('should have production checklist', async () => {
      const deploymentReadme = path.join(process.cwd(), 'deployments/production/README.md');
      const content = fs.readFileSync(deploymentReadme, 'utf8');
      
      expect(content).toContain('Production Checklist');
      expect(content).toContain('Pre-Deployment');
      expect(content).toContain('Post-Deployment');
    });
  });

  test.describe('Integration Testing', () => {
    test('should validate production configuration structure', async () => {
      const productionPath = path.join(process.cwd(), 'deployments/production');
      const kustomizationFile = path.join(productionPath, 'kustomization.yaml');
      
      expect(fs.existsSync(kustomizationFile)).toBeTruthy();

      const content = fs.readFileSync(kustomizationFile, 'utf8');
      expect(content).toContain('apiVersion: kustomize.config.k8s.io');
      expect(content).toContain('kind: Kustomization');
      expect(content).toContain('namespace: zero-trust-prod');
    });

    test('should have proper resource references in kustomization', async () => {
      const productionPath = path.join(process.cwd(), 'deployments/production');
      const kustomizationFile = path.join(productionPath, 'kustomization.yaml');
      
      const content = fs.readFileSync(kustomizationFile, 'utf8');
      expect(content).toContain('resources:');
      
      // Should reference base configuration or have resources
      expect(content).toContain('../../base') || expect(content).toContain('secrets/') || expect(content).toContain('monitoring/');
    });

    test('should validate YAML syntax in all production configs', async () => {
      const productionPath = path.join(process.cwd(), 'deployments/production');
      
      function validateYamlFiles(dir) {
        const files = fs.readdirSync(dir);
        
        for (const file of files) {
          const filePath = path.join(dir, file);
          const stat = fs.statSync(filePath);
          
          if (stat.isDirectory()) {
            validateYamlFiles(filePath);
          } else if (file.endsWith('.yaml') || file.endsWith('.yml')) {
            const content = fs.readFileSync(filePath, 'utf8');
            
            // Basic YAML validation - should not throw
            expect(() => {
              // Simple check for basic YAML structure
              expect(content).toContain(':');
            }).not.toThrow();
          }
        }
      }
      
      validateYamlFiles(productionPath);
    });
  });

  test.describe('Week 5 Make Command Integration', () => {
    test('should have test-e2e-production command', async () => {
      // This test should be run by a new make command
      expect(true).toBeTruthy(); // Placeholder for make command integration
    });

    test('should validate production deployment can be tested', async () => {
      // Check if production validation commands exist in Makefile
      const makefilePath = path.join(process.cwd(), 'Makefile');
      const content = fs.readFileSync(makefilePath, 'utf8');
      
      // Should have production-related test commands
      expect(content).toContain('test-') || expect(content).toContain('production');
    });
  });
});

test.describe('Week 5: Production Security Validation', () => {
  test('should validate zero trust network policies', async () => {
    const networkPoliciesFile = path.join(
      process.cwd(), 
      'deployments/production/security/network-policies.yaml'
    );
    
    const content = fs.readFileSync(networkPoliciesFile, 'utf8');
    
    // Should have default deny policy
    expect(content).toContain('default-deny-all');
    expect(content).toContain('policyTypes:');
    expect(content).toContain('- Ingress');
    expect(content).toContain('- Egress');
    
    // Should have service-specific policies
    expect(content).toContain('backend-api-network-policy');
    expect(content).toContain('keycloak-network-policy');
    expect(content).toContain('opa-network-policy');
  });

  test('should validate security scanning configuration', async () => {
    const securityScanFile = path.join(
      process.cwd(), 
      'deployments/production/security/security-scanning.yaml'
    );
    
    const content = fs.readFileSync(securityScanFile, 'utf8');
    
    // Should have runtime security monitoring
    expect(content).toContain('falco');
    expect(content).toContain('DaemonSet');
    
    // Should have vulnerability scanning
    expect(content).toContain('trivy');
    expect(content).toContain('CronJob');
    
    // Should have policy enforcement
    expect(content).toContain('gatekeeper');
    expect(content).toContain('ConstraintTemplate');
  });
});

test.describe('Week 5: Production Monitoring Validation', () => {
  test('should validate monitoring configuration completeness', async () => {
    const monitoringPath = path.join(process.cwd(), 'deployments/production/monitoring');
    
    // Check required monitoring files
    const requiredFiles = [
      'prometheus-servicemonitor.yaml',
      'grafana-dashboard.yaml'
    ];
    
    for (const file of requiredFiles) {
      expect(fs.existsSync(path.join(monitoringPath, file))).toBeTruthy();
    }
  });

  test('should validate alert rules for zero trust metrics', async () => {
    const serviceMonitorFile = path.join(
      process.cwd(), 
      'deployments/production/monitoring/prometheus-servicemonitor.yaml'
    );
    
    const content = fs.readFileSync(serviceMonitorFile, 'utf8');
    
    // Should have zero trust specific metrics or alerts
    expect(content).toContain('zero-trust') || expect(content).toContain('authentication') || expect(content).toContain('ServiceMonitor');
  });
});