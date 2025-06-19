package valueobjects

import (
	"fmt"
	"regexp"
	"strings"
)

// Username represents a username value object
type Username struct {
	value string
}

// usernameRegex defines valid username format (alphanumeric, underscore, hyphen)
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// NewUsername creates a new username value object
func NewUsername(username string) (Username, error) {
	username = strings.TrimSpace(username)

	if username == "" {
		return Username{}, fmt.Errorf("username cannot be empty")
	}

	if len(username) < 3 {
		return Username{}, fmt.Errorf("username must be at least 3 characters long")
	}

	if len(username) > 50 {
		return Username{}, fmt.Errorf("username too long (max 50 characters)")
	}

	if !usernameRegex.MatchString(username) {
		return Username{}, fmt.Errorf("username can only contain alphanumeric characters, underscores, and hyphens")
	}

	// Check for reserved usernames
	reserved := []string{"admin", "root", "system", "api", "www", "ftp", "mail", "test"}
	lowerUsername := strings.ToLower(username)
	for _, r := range reserved {
		if lowerUsername == r {
			return Username{}, fmt.Errorf("username '%s' is reserved", username)
		}
	}

	return Username{value: username}, nil
}

// String returns the string representation of the username
func (u Username) String() string {
	return u.value
}

// IsEmpty checks if the username is empty
func (u Username) IsEmpty() bool {
	return u.value == ""
}

// Equals checks if two usernames are equal
func (u Username) Equals(other Username) bool {
	return u.value == other.value
}

// Length returns the length of the username
func (u Username) Length() int {
	return len(u.value)
}

// Validate validates the username
func (u Username) Validate() error {
	if u.IsEmpty() {
		return fmt.Errorf("username cannot be empty")
	}

	if len(u.value) < 3 {
		return fmt.Errorf("username must be at least 3 characters long")
	}

	if len(u.value) > 50 {
		return fmt.Errorf("username too long (max 50 characters)")
	}

	if !usernameRegex.MatchString(u.value) {
		return fmt.Errorf("username can only contain alphanumeric characters, underscores, and hyphens")
	}

	return nil
}
