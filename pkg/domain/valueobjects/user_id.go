// Package valueobjects provides domain value objects for the MVP Zero Trust Auth system.
// Value objects are immutable objects that represent concepts with intrinsic value.
package valueobjects

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// UserID represents a unique user identifier
type UserID struct {
	id string
}

// NewUserID creates a new user ID with a generated UUID
func NewUserID() UserID {
	return UserID{
		id: uuid.New().String(),
	}
}

// ParseUserID parses a string into a UserID
func ParseUserID(id string) (UserID, error) {
	if strings.TrimSpace(id) == "" {
		return UserID{}, fmt.Errorf("user ID cannot be empty")
	}

	// Validate UUID format
	if _, err := uuid.Parse(id); err != nil {
		return UserID{}, fmt.Errorf("invalid user ID format: %w", err)
	}

	return UserID{id: id}, nil
}

// String returns the string representation of the user ID
func (uid UserID) String() string {
	return uid.id
}

// IsEmpty checks if the user ID is empty
func (uid UserID) IsEmpty() bool {
	return uid.id == ""
}

// Equals checks if two user IDs are equal
func (uid UserID) Equals(other UserID) bool {
	return uid.id == other.id
}

// Validate validates the user ID
func (uid UserID) Validate() error {
	if uid.IsEmpty() {
		return fmt.Errorf("user ID cannot be empty")
	}

	// Validate UUID format
	if _, err := uuid.Parse(uid.id); err != nil {
		return fmt.Errorf("invalid user ID format: %w", err)
	}

	return nil
}
