# public.users

## Description

## Columns

| Name | Type | Default | Nullable | Children | Parents | Comment |
| ---- | ---- | ------- | -------- | -------- | ------- | ------- |
| id | uuid | gen_random_uuid() | false | [public.device_attestations](public.device_attestations.md) [public.compliance_audit_logs](public.compliance_audit_logs.md) [public.consent_records](public.consent_records.md) |  |  |
| username | varchar(50) |  | false |  |  |  |
| email | varchar(100) |  | false |  |  |  |
| password_hash | varchar(255) |  | false |  |  |  |
| first_name | varchar(50) |  | true |  |  |  |
| last_name | varchar(50) |  | true |  |  |  |
| is_active | boolean | true | true |  |  |  |
| is_admin | boolean | false | true |  |  |  |
| failed_login_attempts | integer | 0 | true |  |  |  |
| last_failed_login_at | timestamp with time zone |  | true |  |  |  |
| account_locked_at | timestamp with time zone |  | true |  |  |  |
| account_locked_until | timestamp with time zone |  | true |  |  |  |
| last_login_at | timestamp with time zone |  | true |  |  |  |
| last_login_ip | varchar(45) |  | true |  |  |  |
| created_at | timestamp with time zone | CURRENT_TIMESTAMP | true |  |  |  |
| updated_at | timestamp with time zone | CURRENT_TIMESTAMP | true |  |  |  |
| deleted_at | timestamp with time zone |  | true |  |  |  |

## Constraints

| Name | Type | Definition |
| ---- | ---- | ---------- |
| users_pkey | PRIMARY KEY | PRIMARY KEY (id) |
| users_username_key | UNIQUE | UNIQUE (username) |
| users_email_key | UNIQUE | UNIQUE (email) |

## Indexes

| Name | Definition |
| ---- | ---------- |
| users_pkey | CREATE UNIQUE INDEX users_pkey ON public.users USING btree (id) |
| users_username_key | CREATE UNIQUE INDEX users_username_key ON public.users USING btree (username) |
| users_email_key | CREATE UNIQUE INDEX users_email_key ON public.users USING btree (email) |
| idx_users_username | CREATE INDEX idx_users_username ON public.users USING btree (username) |
| idx_users_email | CREATE INDEX idx_users_email ON public.users USING btree (email) |
| idx_users_active | CREATE INDEX idx_users_active ON public.users USING btree (is_active) |
| idx_users_email_active | CREATE INDEX idx_users_email_active ON public.users USING btree (email) WHERE (is_active = true) |
| idx_users_username_active | CREATE INDEX idx_users_username_active ON public.users USING btree (username) WHERE (is_active = true) |
| idx_users_failed_login_attempts | CREATE INDEX idx_users_failed_login_attempts ON public.users USING btree (failed_login_attempts) WHERE (failed_login_attempts > 0) |
| idx_users_account_locked | CREATE INDEX idx_users_account_locked ON public.users USING btree (account_locked_until) WHERE (account_locked_until IS NOT NULL) |
| idx_users_last_login | CREATE INDEX idx_users_last_login ON public.users USING btree (last_login_at DESC) |
| idx_users_deleted_at | CREATE INDEX idx_users_deleted_at ON public.users USING btree (deleted_at) |
| idx_users_account_locked_until | CREATE INDEX idx_users_account_locked_until ON public.users USING btree (account_locked_until) |

## Relations

```mermaid
erDiagram

"public.device_attestations" }o--|| "public.users" : "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE"
"public.compliance_audit_logs" }o--o| "public.users" : "FOREIGN KEY (user_id) REFERENCES users(id)"
"public.consent_records" }o--o| "public.users" : "FOREIGN KEY (user_id) REFERENCES users(id)"

"public.users" {
  uuid id
  varchar_50_ username
  varchar_100_ email
  varchar_255_ password_hash
  varchar_50_ first_name
  varchar_50_ last_name
  boolean is_active
  boolean is_admin
  integer failed_login_attempts
  timestamp_with_time_zone last_failed_login_at
  timestamp_with_time_zone account_locked_at
  timestamp_with_time_zone account_locked_until
  timestamp_with_time_zone last_login_at
  varchar_45_ last_login_ip
  timestamp_with_time_zone created_at
  timestamp_with_time_zone updated_at
  timestamp_with_time_zone deleted_at
}
"public.device_attestations" {
  uuid id
  uuid user_id FK
  varchar_255_ device_id
  varchar_100_ device_name
  varchar_50_ platform
  varchar_255_ spiffe_id
  varchar_255_ workload_selector
  jsonb attestation_data
  varchar_20_ status
  integer trust_level
  boolean is_verified
  timestamp_with_time_zone verified_at
  timestamp_with_time_zone expires_at
  timestamp_with_time_zone created_at
  timestamp_with_time_zone updated_at
}
"public.compliance_audit_logs" {
  uuid id
  timestamp_with_time_zone created_at
  timestamp_with_time_zone updated_at
  timestamp_with_time_zone deleted_at
  uuid user_id FK
  varchar_100_ action
  varchar_100_ resource
  jsonb details
  boolean success
  varchar_500_ error_msg
  varchar_45_ ip_address
  varchar_500_ user_agent
  varchar_100_ request_id
  varchar_100_ session_id
  varchar_100_ tenant_id
  varchar_200_ compliance_frameworks
  varchar_50_ data_classification
  integer sensitivity_level
  varchar_50_ legal_basis
  jsonb data_subjects
  jsonb data_categories
  varchar_500_ processing_purpose
  varchar_10_ geolocation_country
  integer risk_score
  jsonb controls_applied
  boolean approval_required
  varchar_50_ approval_status
  varchar_50_ review_status
  varchar_50_ retention_category
  varchar_1000_ business_justification
  timestamp_with_time_zone retain_until
  timestamp_with_time_zone archive_date
  timestamp_with_time_zone purge_date
  boolean archived
  timestamp_with_time_zone archived_at
  jsonb business_context
  jsonb technical_context
}
"public.consent_records" {
  uuid id
  timestamp_with_time_zone created_at
  timestamp_with_time_zone updated_at
  timestamp_with_time_zone deleted_at
  varchar_255_ data_subject
  uuid user_id FK
  varchar_100_ consent_type
  varchar_500_ purpose
  varchar_100_ legal_basis
  jsonb data_categories
  varchar_50_ status
  boolean consent_given
  timestamp_with_time_zone consent_date
  timestamp_with_time_zone withdrawn_date
  timestamp_with_time_zone expiry_date
  varchar_100_ consent_method
  text consent_text
  varchar_20_ consent_version
  varchar_45_ ip_address
  varchar_500_ user_agent
  jsonb consent_proof
  varchar_100_ withdrawal_method
  varchar_500_ withdrawal_reason
}
```

---

> Generated by [tbls](https://github.com/k1LoW/tbls)
