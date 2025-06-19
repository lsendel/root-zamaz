// Package queries provides application layer queries for the MVP Zero Trust Auth system.
// Queries represent operations that read data without changing the state of the system.
package queries

import (
	"context"
	"time"
)

// UserQueries interface defines all user-related queries
type UserQueries interface {
	GetUser(ctx context.Context, query GetUserQuery) (*UserView, error)
	GetUserByEmail(ctx context.Context, query GetUserByEmailQuery) (*UserView, error)
	GetUserByUsername(ctx context.Context, query GetUserByUsernameQuery) (*UserView, error)
	ListUsers(ctx context.Context, query ListUsersQuery) (*UserListView, error)
	GetUserSessions(ctx context.Context, query GetUserSessionsQuery) (*SessionListView, error)
	GetUserAuditLog(ctx context.Context, query GetUserAuditLogQuery) (*AuditLogView, error)
}

// GetUserQuery represents a query to get a user by ID
type GetUserQuery struct {
	UserID string
}

// GetUserByEmailQuery represents a query to get a user by email
type GetUserByEmailQuery struct {
	Email string
}

// GetUserByUsernameQuery represents a query to get a user by username
type GetUserByUsernameQuery struct {
	Username string
}

// ListUsersQuery represents a query to list users with pagination
type ListUsersQuery struct {
	Page     int
	PageSize int
	Search   string
	IsActive *bool
	IsAdmin  *bool
	SortBy   string
	SortDesc bool
}

// GetUserSessionsQuery represents a query to get user sessions
type GetUserSessionsQuery struct {
	UserID   string
	Page     int
	PageSize int
	Active   *bool
}

// GetUserAuditLogQuery represents a query to get user audit log
type GetUserAuditLogQuery struct {
	UserID    string
	Page      int
	PageSize  int
	EventType string
	StartDate *time.Time
	EndDate   *time.Time
}

// View Models

// UserView represents a user view model
type UserView struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	IsActive  bool      `json:"is_active"`
	IsAdmin   bool      `json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Security Information
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP         string     `json:"last_login_ip,omitempty"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	AccountLockedUntil  *time.Time `json:"account_locked_until,omitempty"`
	MFAEnabled          bool       `json:"mfa_enabled"`
}

// UserListView represents a paginated list of users
type UserListView struct {
	Users      []UserView `json:"users"`
	Total      int64      `json:"total"`
	Page       int        `json:"page"`
	PageSize   int        `json:"page_size"`
	TotalPages int        `json:"total_pages"`
}

// SessionView represents a session view model
type SessionView struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	DeviceID  string    `json:"device_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IsActive  bool      `json:"is_active"`
	LastUsed  time.Time `json:"last_used"`
}

// SessionListView represents a paginated list of sessions
type SessionListView struct {
	Sessions   []SessionView `json:"sessions"`
	Total      int64         `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int           `json:"total_pages"`
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	EventType   string                 `json:"event_type"`
	EventData   map[string]interface{} `json:"event_data"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	OccurredAt  time.Time              `json:"occurred_at"`
}

// AuditLogView represents a paginated audit log
type AuditLogView struct {
	Entries    []AuditLogEntry `json:"entries"`
	Total      int64           `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalPages int             `json:"total_pages"`
}