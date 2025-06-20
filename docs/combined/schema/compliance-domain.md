# Compliance & Data Governance Domain

## Overview
This domain ensures regulatory compliance with GDPR, HIPAA, SOC2, and other frameworks through comprehensive audit logging, data subject rights management, consent tracking, and automated compliance reporting.

## Tables in this Domain

| Table | Purpose | Details |
|-------|---------|---------|
| [compliance_audit_logs](public.compliance_audit_logs.md) | Compliance-specific audit events | Framework tagging, data classification, retention policies |
| [compliance_violations](public.compliance_violations.md) | Detected compliance policy violations | Risk scoring, remediation tracking, resolution workflow |
| [data_subject_requests](public.data_subject_requests.md) | GDPR data subject access/deletion requests | Identity verification, request workflow, compliance tracking |
| [consent_records](public.consent_records.md) | User privacy consent tracking | Granular consent, withdrawal tracking, proof of consent |
| [retention_policies](public.retention_policies.md) | Data retention policy definitions | Automated retention, legal hold, policy enforcement |
| [compliance_reports](public.compliance_reports.md) | Generated compliance assessment reports | Automated reporting, executive summaries, audit findings |

## GDPR Compliance Flow

```mermaid
sequenceDiagram
    participant DS as Data Subject
    participant PR as Privacy Portal
    participant DS as DSR Service
    participant V as Verification Service
    participant P as Processing Service
    participant A as Audit Service
    
    DS->>PR: Submit Request (Art. 15-22)
    PR->>+data_subject_requests: Create Request
    data_subject_requests-->>-PR: Request ID
    
    PR->>V: Verify Identity
    V->>+data_subject_requests: Update Verification
    data_subject_requests-->>-V: Status Updated
    
    V->>P: Process Request
    P->>+compliance_audit_logs: Log Processing
    compliance_audit_logs-->>-P: Audit Logged
    P->>+data_subject_requests: Update Response
    data_subject_requests-->>-P: Response Stored
    
    P->>A: Generate Compliance Report
    A->>+compliance_reports: Store Report
    compliance_reports-->>-A: Report Generated
```

## Consent Management Flow

```mermaid
graph TD
    A[User Interaction] --> B{Consent Required?}
    B -->|Yes| C[Present Consent Form]
    B -->|No| D[Proceed]
    
    C --> E[User Decision]
    E -->|Accept| F[consent_records: Store Consent]
    E -->|Reject| G[consent_records: Store Rejection]
    E -->|Withdraw| H[consent_records: Store Withdrawal]
    
    F --> I[Enable Processing]
    G --> J[Block Processing]
    H --> K[Stop Processing]
    
    L[Consent Expiry] --> M[compliance_audit_logs: Log Expiry]
    M --> N[Request Renewal]
```

## Violation Detection & Remediation

```mermaid
graph LR
    A[compliance_audit_logs] --> B[Policy Engine]
    B --> C{Violation Detected?}
    C -->|Yes| D[compliance_violations: Create]
    C -->|No| E[Continue Monitoring]
    
    D --> F[Risk Assessment]
    F --> G[Assign Remediation]
    G --> H[Track Resolution]
    H --> I[compliance_violations: Update]
    
    J[Automated Reports] --> K[compliance_reports]
    I --> J
```

## Data Retention Lifecycle

```mermaid
graph TD
    A[Data Creation] --> B[retention_policies: Apply Policy]
    B --> C[compliance_audit_logs: Log Classification]
    C --> D[Active Data]
    
    D --> E{Retention Period Expired?}
    E -->|No| F[Continue Storage]
    E -->|Yes| G[Archive Data]
    
    G --> H{Archive Period Expired?}
    H -->|No| I[Archived Storage]
    H -->|Yes| J[Secure Deletion]
    
    K[Legal Hold] --> L[Override Deletion]
    L --> M[retention_policies: Exception]
```

## Key Compliance Features

### GDPR Compliance
- **Data Subject Rights**: Complete GDPR Article 15-22 support
- **Consent Management**: Granular consent tracking and withdrawal
- **Data Portability**: Structured data export capabilities
- **Right to Erasure**: Automated data deletion workflows
- **Privacy by Design**: Built-in privacy protection mechanisms

### Automated Compliance Monitoring
- **Policy Violations**: Real-time compliance violation detection
- **Risk Scoring**: Automated risk assessment for compliance events
- **Control Effectiveness**: Monitoring of security control effectiveness
- **Gap Analysis**: Identification of compliance gaps and weaknesses
- **Trend Analysis**: Long-term compliance trend monitoring

### Data Governance Framework
- **Data Classification**: Sensitivity levels and categories
- **Lifecycle Management**: Creation to deletion tracking
- **Access Controls**: Role-based data access restrictions
- **Audit Trails**: Complete data processing audit trails
- **Retention Enforcement**: Automated policy enforcement

## Related Domains
- [Authentication & Authorization](auth-domain.md) - User identity and access management
- [Security & Monitoring](security-domain.md) - Security monitoring and incident response
- [Zero Trust & Device Security](zero-trust-domain.md) - Device trust and attestation