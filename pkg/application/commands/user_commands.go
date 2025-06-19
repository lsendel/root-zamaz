// Package commands provides application layer commands for the MVP Zero Trust Auth system.
// Commands represent operations that change the state of the system.
package commands

import (
	"context"
	"time"
)

// UserCommands interface defines all user-related commands
type UserCommands interface {
	CreateUser(ctx context.Context, cmd CreateUserCommand) (*CreateUserResult, error)
	UpdateUser(ctx context.Context, cmd UpdateUserCommand) error
	ChangePassword(ctx context.Context, cmd ChangePasswordCommand) error
	ActivateUser(ctx context.Context, cmd ActivateUserCommand) error
	DeactivateUser(ctx context.Context, cmd DeactivateUserCommand) error
	PromoteToAdmin(ctx context.Context, cmd PromoteToAdminCommand) error
	DemoteFromAdmin(ctx context.Context, cmd DemoteFromAdminCommand) error
	RecordLogin(ctx context.Context, cmd RecordLoginCommand) error
	RecordFailedLogin(ctx context.Context, cmd RecordFailedLoginCommand) error
	UnlockAccount(ctx context.Context, cmd UnlockAccountCommand) error
	EnableMFA(ctx context.Context, cmd EnableMFACommand) error
	DisableMFA(ctx context.Context, cmd DisableMFACommand) error
}

// CreateUserCommand represents a command to create a new user
type CreateUserCommand struct {
	Email     string
	Username  string
	Password  string
	FirstName string
	LastName  string
}

// CreateUserResult represents the result of creating a user
type CreateUserResult struct {
	UserID    string
	Email     string
	Username  string
	CreatedAt time.Time
}

// UpdateUserCommand represents a command to update user information
type UpdateUserCommand struct {
	UserID    string
	Email     *string
	Username  *string
	FirstName *string
	LastName  *string
}

// ChangePasswordCommand represents a command to change a user's password
type ChangePasswordCommand struct {
	UserID      string
	OldPassword string
	NewPassword string
}

// ActivateUserCommand represents a command to activate a user account
type ActivateUserCommand struct {
	UserID string
}

// DeactivateUserCommand represents a command to deactivate a user account
type DeactivateUserCommand struct {
	UserID string
}

// PromoteToAdminCommand represents a command to promote a user to admin
type PromoteToAdminCommand struct {
	UserID string
}

// DemoteFromAdminCommand represents a command to demote a user from admin
type DemoteFromAdminCommand struct {
	UserID string
}

// RecordLoginCommand represents a command to record a successful login
type RecordLoginCommand struct {
	UserID    string
	IPAddress string
}

// RecordFailedLoginCommand represents a command to record a failed login attempt
type RecordFailedLoginCommand struct {
	UserID           string
	IPAddress        string
	MaxAttempts      int
	LockoutDuration  time.Duration
}

// UnlockAccountCommand represents a command to manually unlock a user account
type UnlockAccountCommand struct {
	UserID string
}

// EnableMFACommand represents a command to enable MFA for a user
type EnableMFACommand struct {
	UserID string
	Secret string
}

// DisableMFACommand represents a command to disable MFA for a user
type DisableMFACommand struct {
	UserID string
}