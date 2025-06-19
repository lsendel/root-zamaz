package valueobjects

import (
	"fmt"
	"regexp"
	"strings"
)

// Email represents an email address value object
type Email struct {
	value string
}

// emailRegex is a basic email validation regex
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// NewEmail creates a new email value object
func NewEmail(email string) (Email, error) {
	email = strings.TrimSpace(strings.ToLower(email))

	if email == "" {
		return Email{}, fmt.Errorf("email cannot be empty")
	}

	if len(email) > 254 {
		return Email{}, fmt.Errorf("email too long (max 254 characters)")
	}

	if !emailRegex.MatchString(email) {
		return Email{}, fmt.Errorf("invalid email format")
	}

	return Email{value: email}, nil
}

// String returns the string representation of the email
func (e Email) String() string {
	return e.value
}

// IsEmpty checks if the email is empty
func (e Email) IsEmpty() bool {
	return e.value == ""
}

// Equals checks if two emails are equal
func (e Email) Equals(other Email) bool {
	return e.value == other.value
}

// Domain returns the domain part of the email
func (e Email) Domain() string {
	parts := strings.Split(e.value, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// LocalPart returns the local part of the email (before @)
func (e Email) LocalPart() string {
	parts := strings.Split(e.value, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// Validate validates the email
func (e Email) Validate() error {
	if e.IsEmpty() {
		return fmt.Errorf("email cannot be empty")
	}

	if len(e.value) > 254 {
		return fmt.Errorf("email too long (max 254 characters)")
	}

	if !emailRegex.MatchString(e.value) {
		return fmt.Errorf("invalid email format")
	}

	return nil
}
