package valueobjects

import (
	"fmt"
	"strings"
)

// PasswordHash represents a hashed password value object
type PasswordHash struct {
	hash string
}

// NewPasswordHash creates a new password hash value object
func NewPasswordHash(hash string) (PasswordHash, error) {
	hash = strings.TrimSpace(hash)

	if hash == "" {
		return PasswordHash{}, fmt.Errorf("password hash cannot be empty")
	}

	// Basic validation for bcrypt hash format
	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2y$") {
		return PasswordHash{}, fmt.Errorf("invalid password hash format")
	}

	if len(hash) != 60 {
		return PasswordHash{}, fmt.Errorf("invalid password hash length")
	}

	return PasswordHash{hash: hash}, nil
}

// String returns the string representation of the password hash
func (ph PasswordHash) String() string {
	return ph.hash
}

// IsEmpty checks if the password hash is empty
func (ph PasswordHash) IsEmpty() bool {
	return ph.hash == ""
}

// Equals checks if two password hashes are equal
func (ph PasswordHash) Equals(other PasswordHash) bool {
	return ph.hash == other.hash
}

// Algorithm returns the hashing algorithm used
func (ph PasswordHash) Algorithm() string {
	if strings.HasPrefix(ph.hash, "$2a$") {
		return "bcrypt-2a"
	}
	if strings.HasPrefix(ph.hash, "$2b$") {
		return "bcrypt-2b"
	}
	if strings.HasPrefix(ph.hash, "$2y$") {
		return "bcrypt-2y"
	}
	return "unknown"
}

// Cost returns the bcrypt cost factor
func (ph PasswordHash) Cost() string {
	parts := strings.Split(ph.hash, "$")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// Validate validates the password hash
func (ph PasswordHash) Validate() error {
	if ph.IsEmpty() {
		return fmt.Errorf("password hash cannot be empty")
	}

	if !strings.HasPrefix(ph.hash, "$2a$") && !strings.HasPrefix(ph.hash, "$2b$") && !strings.HasPrefix(ph.hash, "$2y$") {
		return fmt.Errorf("invalid password hash format")
	}

	if len(ph.hash) != 60 {
		return fmt.Errorf("invalid password hash length")
	}

	return nil
}
