// Package repositories provides domain repository interfaces for the MVP Zero Trust Auth system.
// These interfaces define the contracts for data persistence without specifying implementation details.
package repositories

import (
	"context"

	"mvp.local/pkg/domain/entities"
)

// UserRepository defines the contract for user data persistence
type UserRepository interface {
	// Save saves a user entity
	Save(ctx context.Context, user *entities.User) error

	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id string) (*entities.User, error)

	// GetByEmail retrieves a user by email address
	GetByEmail(ctx context.Context, email string) (*entities.User, error)

	// GetByUsername retrieves a user by username
	GetByUsername(ctx context.Context, username string) (*entities.User, error)

	// List retrieves a paginated list of users
	List(ctx context.Context, criteria ListUsersCriteria) (*UserListResult, error)

	// Delete deletes a user by ID
	Delete(ctx context.Context, id string) error

	// Exists checks if a user exists by ID
	Exists(ctx context.Context, id string) (bool, error)

	// ExistsByEmail checks if a user exists by email
	ExistsByEmail(ctx context.Context, email string) (bool, error)

	// ExistsByUsername checks if a user exists by username
	ExistsByUsername(ctx context.Context, username string) (bool, error)

	// Count returns the total number of users matching the criteria
	Count(ctx context.Context, criteria CountUsersCriteria) (int64, error)
}

// ListUsersCriteria defines criteria for listing users
type ListUsersCriteria struct {
	Page     int
	PageSize int
	Search   string
	IsActive *bool
	IsAdmin  *bool
	SortBy   string
	SortDesc bool
}

// CountUsersCriteria defines criteria for counting users
type CountUsersCriteria struct {
	Search   string
	IsActive *bool
	IsAdmin  *bool
}

// UserListResult represents the result of a user list query
type UserListResult struct {
	Users      []*entities.User
	Total      int64
	Page       int
	PageSize   int
	TotalPages int
}
