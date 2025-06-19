package events

import "time"

// User Events

// UserCreated event is raised when a new user is created
type UserCreated struct {
	BaseEvent
}

// NewUserCreated creates a new UserCreated event
func NewUserCreated(userID, email, username string, occurredAt time.Time) *UserCreated {
	data := map[string]interface{}{
		"email":    email,
		"username": username,
	}

	event := &UserCreated{
		BaseEvent: NewBaseEvent("UserCreated", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserEmailChanged event is raised when a user's email is changed
type UserEmailChanged struct {
	BaseEvent
}

// NewUserEmailChanged creates a new UserEmailChanged event
func NewUserEmailChanged(userID, oldEmail, newEmail string, occurredAt time.Time) *UserEmailChanged {
	data := map[string]interface{}{
		"old_email": oldEmail,
		"new_email": newEmail,
	}

	event := &UserEmailChanged{
		BaseEvent: NewBaseEvent("UserEmailChanged", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserUsernameChanged event is raised when a user's username is changed
type UserUsernameChanged struct {
	BaseEvent
}

// NewUserUsernameChanged creates a new UserUsernameChanged event
func NewUserUsernameChanged(userID, oldUsername, newUsername string, occurredAt time.Time) *UserUsernameChanged {
	data := map[string]interface{}{
		"old_username": oldUsername,
		"new_username": newUsername,
	}

	event := &UserUsernameChanged{
		BaseEvent: NewBaseEvent("UserUsernameChanged", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserPasswordChanged event is raised when a user's password is changed
type UserPasswordChanged struct {
	BaseEvent
}

// NewUserPasswordChanged creates a new UserPasswordChanged event
func NewUserPasswordChanged(userID string, occurredAt time.Time) *UserPasswordChanged {
	data := map[string]interface{}{}

	event := &UserPasswordChanged{
		BaseEvent: NewBaseEvent("UserPasswordChanged", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserProfileUpdated event is raised when a user's profile is updated
type UserProfileUpdated struct {
	BaseEvent
}

// NewUserProfileUpdated creates a new UserProfileUpdated event
func NewUserProfileUpdated(userID string, occurredAt time.Time) *UserProfileUpdated {
	data := map[string]interface{}{}

	event := &UserProfileUpdated{
		BaseEvent: NewBaseEvent("UserProfileUpdated", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserActivated event is raised when a user account is activated
type UserActivated struct {
	BaseEvent
}

// NewUserActivated creates a new UserActivated event
func NewUserActivated(userID string, occurredAt time.Time) *UserActivated {
	data := map[string]interface{}{}

	event := &UserActivated{
		BaseEvent: NewBaseEvent("UserActivated", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserDeactivated event is raised when a user account is deactivated
type UserDeactivated struct {
	BaseEvent
}

// NewUserDeactivated creates a new UserDeactivated event
func NewUserDeactivated(userID string, occurredAt time.Time) *UserDeactivated {
	data := map[string]interface{}{}

	event := &UserDeactivated{
		BaseEvent: NewBaseEvent("UserDeactivated", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserPromotedToAdmin event is raised when a user is promoted to admin
type UserPromotedToAdmin struct {
	BaseEvent
}

// NewUserPromotedToAdmin creates a new UserPromotedToAdmin event
func NewUserPromotedToAdmin(userID string, occurredAt time.Time) *UserPromotedToAdmin {
	data := map[string]interface{}{}

	event := &UserPromotedToAdmin{
		BaseEvent: NewBaseEvent("UserPromotedToAdmin", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserDemotedFromAdmin event is raised when a user is demoted from admin
type UserDemotedFromAdmin struct {
	BaseEvent
}

// NewUserDemotedFromAdmin creates a new UserDemotedFromAdmin event
func NewUserDemotedFromAdmin(userID string, occurredAt time.Time) *UserDemotedFromAdmin {
	data := map[string]interface{}{}

	event := &UserDemotedFromAdmin{
		BaseEvent: NewBaseEvent("UserDemotedFromAdmin", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserLoggedIn event is raised when a user successfully logs in
type UserLoggedIn struct {
	BaseEvent
}

// NewUserLoggedIn creates a new UserLoggedIn event
func NewUserLoggedIn(userID, ipAddress string, occurredAt time.Time) *UserLoggedIn {
	data := map[string]interface{}{
		"ip_address": ipAddress,
	}

	event := &UserLoggedIn{
		BaseEvent: NewBaseEvent("UserLoggedIn", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserLoginFailed event is raised when a user login attempt fails
type UserLoginFailed struct {
	BaseEvent
}

// NewUserLoginFailed creates a new UserLoginFailed event
func NewUserLoginFailed(userID, ipAddress string, failedAttempts int, occurredAt time.Time) *UserLoginFailed {
	data := map[string]interface{}{
		"ip_address":      ipAddress,
		"failed_attempts": failedAttempts,
	}

	event := &UserLoginFailed{
		BaseEvent: NewBaseEvent("UserLoginFailed", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserAccountLocked event is raised when a user account is locked due to failed login attempts
type UserAccountLocked struct {
	BaseEvent
}

// NewUserAccountLocked creates a new UserAccountLocked event
func NewUserAccountLocked(userID string, failedAttempts int, lockedUntil, occurredAt time.Time) *UserAccountLocked {
	data := map[string]interface{}{
		"failed_attempts": failedAttempts,
		"locked_until":    lockedUntil,
	}

	event := &UserAccountLocked{
		BaseEvent: NewBaseEvent("UserAccountLocked", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserAccountUnlocked event is raised when a user account is manually unlocked
type UserAccountUnlocked struct {
	BaseEvent
}

// NewUserAccountUnlocked creates a new UserAccountUnlocked event
func NewUserAccountUnlocked(userID string, occurredAt time.Time) *UserAccountUnlocked {
	data := map[string]interface{}{}

	event := &UserAccountUnlocked{
		BaseEvent: NewBaseEvent("UserAccountUnlocked", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserMFAEnabled event is raised when MFA is enabled for a user
type UserMFAEnabled struct {
	BaseEvent
}

// NewUserMFAEnabled creates a new UserMFAEnabled event
func NewUserMFAEnabled(userID string, occurredAt time.Time) *UserMFAEnabled {
	data := map[string]interface{}{}

	event := &UserMFAEnabled{
		BaseEvent: NewBaseEvent("UserMFAEnabled", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}

// UserMFADisabled event is raised when MFA is disabled for a user
type UserMFADisabled struct {
	BaseEvent
}

// NewUserMFADisabled creates a new UserMFADisabled event
func NewUserMFADisabled(userID string, occurredAt time.Time) *UserMFADisabled {
	data := map[string]interface{}{}

	event := &UserMFADisabled{
		BaseEvent: NewBaseEvent("UserMFADisabled", userID, data),
	}
	event.occurredAt = occurredAt
	return event
}