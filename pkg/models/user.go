// Package models provides database models for the MVP Zero Trust Auth system.
// This package contains GORM models for user management, authentication,
// and authorization using Casbin RBAC integration.
package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system with authentication and profile information
type User struct {
	ID        string         `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Authentication fields
	Username     string `gorm:"uniqueIndex;not null;size:50" json:"username"`
	Email        string `gorm:"uniqueIndex;not null;size:100" json:"email"`
	PasswordHash string `gorm:"not null" json:"-"`

	// Profile fields
	FirstName string `gorm:"size:50" json:"first_name"`
	LastName  string `gorm:"size:50" json:"last_name"`
	IsActive  bool   `gorm:"default:true" json:"is_active"`
	IsAdmin   bool   `gorm:"default:false" json:"is_admin"`

	// Zero Trust fields
	DeviceAttestations []DeviceAttestation `json:"device_attestations,omitempty"`
	Sessions           []UserSession       `json:"sessions,omitempty"`
	
	// RBAC relationships
	Roles []Role `gorm:"many2many:user_roles;" json:"roles,omitempty"`
}

// UserSession represents an active user session for tracking
type UserSession struct {
	ID        string         `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Session tracking
	UserID       string    `gorm:"not null;index;type:uuid" json:"user_id"`
	User         User      `json:"user,omitempty"`
	SessionToken string    `gorm:"uniqueIndex;not null" json:"-"`
	ExpiresAt    time.Time `gorm:"not null" json:"expires_at"`
	IsActive     bool      `gorm:"default:true" json:"is_active"`

	// Device and location tracking
	DeviceID    string `gorm:"size:100" json:"device_id"`
	IPAddress   string `gorm:"size:45" json:"ip_address"`
	UserAgent   string `gorm:"size:500" json:"user_agent"`
	Location    string `gorm:"size:100" json:"location"`
	TrustLevel  int    `gorm:"default:0" json:"trust_level"`
}

// DeviceAttestation represents device attestation data for Zero Trust
type DeviceAttestation struct {
	ID        string         `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Device identification
	UserID     string `gorm:"not null;index;type:uuid" json:"user_id"`
	User       User   `json:"user,omitempty"`
	DeviceID   string `gorm:"uniqueIndex;not null;size:100" json:"device_id"`
	DeviceName string `gorm:"size:100" json:"device_name"`

	// Attestation data
	TrustLevel       int       `gorm:"default:0" json:"trust_level"`
	IsVerified       bool      `gorm:"default:false" json:"is_verified"`
	VerifiedAt       *time.Time `json:"verified_at"`
	AttestationData  string    `gorm:"type:jsonb" json:"attestation_data"` // JSON data
	Platform         string    `gorm:"size:50" json:"platform"`
	
	// SPIRE integration
	SPIFFEID         string    `gorm:"size:200" json:"spiffe_id"`
	WorkloadSelector string    `gorm:"size:200" json:"workload_selector"`
}

// Role represents a role in the RBAC system
type Role struct {
	ID        int64          `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Role definition
	Name        string `gorm:"uniqueIndex;not null;size:50" json:"name"`
	Description string `gorm:"size:200" json:"description"`
	IsActive    bool   `gorm:"default:true" json:"is_active"`

	// RBAC relationships
	Users       []User       `gorm:"many2many:user_roles;" json:"users,omitempty"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
}

// Permission represents a permission in the RBAC system
type Permission struct {
	ID        int64          `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Permission definition
	Name        string `gorm:"uniqueIndex;not null;size:100" json:"name"`
	Resource    string `gorm:"not null;size:50" json:"resource"`
	Action      string `gorm:"not null;size:50" json:"action"`
	Description string `gorm:"size:200" json:"description"`
	IsActive    bool   `gorm:"default:true" json:"is_active"`

	// RBAC relationships
	Roles []Role `gorm:"many2many:role_permissions;" json:"roles,omitempty"`
}

// AuditLog represents system audit logs for security tracking
type AuditLog struct {
	ID        string    `gorm:"primarykey;type:uuid;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	// Audit details
	UserID    *string `gorm:"index;type:uuid" json:"user_id"`
	User      *User  `json:"user,omitempty"`
	Action    string `gorm:"not null;size:100" json:"action"`
	Resource  string `gorm:"size:100" json:"resource"`
	Details   string `gorm:"type:jsonb" json:"details"` // JSON data
	
	// Request context
	IPAddress   string `gorm:"size:45" json:"ip_address"`
	UserAgent   string `gorm:"size:500" json:"user_agent"`
	RequestID   string `gorm:"size:100" json:"request_id"`
	Success     bool   `gorm:"default:false" json:"success"`
	ErrorMsg    string `gorm:"size:500" json:"error_msg"`
}

// TableName methods for custom table names if needed

// TableName sets the table name for User model
func (User) TableName() string {
	return "users"
}

// TableName sets the table name for UserSession model
func (UserSession) TableName() string {
	return "user_sessions"
}

// TableName sets the table name for DeviceAttestation model
func (DeviceAttestation) TableName() string {
	return "device_attestations"
}

// TableName sets the table name for Role model
func (Role) TableName() string {
	return "roles"
}

// TableName sets the table name for Permission model
func (Permission) TableName() string {
	return "permissions"
}

// TableName sets the table name for AuditLog model
func (AuditLog) TableName() string {
	return "audit_logs"
}