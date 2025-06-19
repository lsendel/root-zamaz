// Package entities provides domain entities for the MVP Zero Trust Auth system.
// These entities represent the core business objects and their invariants.
package entities

import (
	"fmt"
	"time"

	"mvp.local/pkg/domain/events"
	"mvp.local/pkg/domain/valueobjects"
)

// User represents a user entity in the domain
type User struct {
	// Identity
	id       valueobjects.UserID
	email    valueobjects.Email
	username valueobjects.Username

	// Profile
	profile *UserProfile

	// Security
	passwordHash valueobjects.PasswordHash
	isActive     bool
	isAdmin      bool

	// Account Security
	securityProfile *SecurityProfile

	// Audit
	createdAt time.Time
	updatedAt time.Time

	// Domain Events
	events []events.DomainEvent
}

// UserProfile contains user profile information
type UserProfile struct {
	FirstName string
	LastName  string
	// Add more profile fields as needed
}

// SecurityProfile contains security-related information
type SecurityProfile struct {
	FailedLoginAttempts int
	LastFailedLoginAt   *time.Time
	AccountLockedAt     *time.Time
	AccountLockedUntil  *time.Time
	LastLoginAt         *time.Time
	LastLoginIP         string
	MFAEnabled          bool
	MFASecrets          []string // Encrypted MFA secrets
}

// UserFactory creates new user instances
type UserFactory struct{}

// NewUserFactory creates a new user factory
func NewUserFactory() *UserFactory {
	return &UserFactory{}
}

// CreateUser creates a new user with the provided details
func (uf *UserFactory) CreateUser(
	email string,
	username string,
	passwordHash string,
	profile *UserProfile,
) (*User, error) {
	// Validate inputs
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	usernameVO, err := valueobjects.NewUsername(username)
	if err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	passwordHashVO, err := valueobjects.NewPasswordHash(passwordHash)
	if err != nil {
		return nil, fmt.Errorf("invalid password hash: %w", err)
	}

	userID := valueobjects.NewUserID()
	now := time.Now()

	user := &User{
		id:           userID,
		email:        emailVO,
		username:     usernameVO,
		profile:      profile,
		passwordHash: passwordHashVO,
		isActive:     true,
		isAdmin:      false,
		securityProfile: &SecurityProfile{
			FailedLoginAttempts: 0,
			MFAEnabled:          false,
			MFASecrets:          make([]string, 0),
		},
		createdAt: now,
		updatedAt: now,
		events:    make([]events.DomainEvent, 0),
	}

	// Raise domain event
	user.addEvent(events.NewUserCreated(
		userID.String(),
		emailVO.String(),
		usernameVO.String(),
		now,
	))

	return user, nil
}

// RestoreUser restores a user from persistence (used by repositories)
func (uf *UserFactory) RestoreUser(
	id string,
	email string,
	username string,
	passwordHash string,
	profile *UserProfile,
	securityProfile *SecurityProfile,
	isActive bool,
	isAdmin bool,
	createdAt time.Time,
	updatedAt time.Time,
) (*User, error) {
	userID, err := valueobjects.ParseUserID(id)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID: %w", err)
	}

	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	usernameVO, err := valueobjects.NewUsername(username)
	if err != nil {
		return nil, fmt.Errorf("invalid username: %w", err)
	}

	passwordHashVO, err := valueobjects.NewPasswordHash(passwordHash)
	if err != nil {
		return nil, fmt.Errorf("invalid password hash: %w", err)
	}

	return &User{
		id:              userID,
		email:           emailVO,
		username:        usernameVO,
		profile:         profile,
		passwordHash:    passwordHashVO,
		isActive:        isActive,
		isAdmin:         isAdmin,
		securityProfile: securityProfile,
		createdAt:       createdAt,
		updatedAt:       updatedAt,
		events:          make([]events.DomainEvent, 0),
	}, nil
}

// Getters
func (u *User) ID() valueobjects.UserID {
	return u.id
}

func (u *User) Email() valueobjects.Email {
	return u.email
}

func (u *User) Username() valueobjects.Username {
	return u.username
}

func (u *User) Profile() *UserProfile {
	return u.profile
}

func (u *User) PasswordHash() valueobjects.PasswordHash {
	return u.passwordHash
}

func (u *User) IsActive() bool {
	return u.isActive
}

func (u *User) IsAdmin() bool {
	return u.isAdmin
}

func (u *User) SecurityProfile() *SecurityProfile {
	return u.securityProfile
}

func (u *User) CreatedAt() time.Time {
	return u.createdAt
}

func (u *User) UpdatedAt() time.Time {
	return u.updatedAt
}

func (u *User) Events() []events.DomainEvent {
	return u.events
}

// Business Methods

// ChangeEmail changes the user's email address
func (u *User) ChangeEmail(newEmail string) error {
	emailVO, err := valueobjects.NewEmail(newEmail)
	if err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	oldEmail := u.email
	u.email = emailVO
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserEmailChanged(
		u.id.String(),
		oldEmail.String(),
		newEmail,
		u.updatedAt,
	))

	return nil
}

// ChangeUsername changes the user's username
func (u *User) ChangeUsername(newUsername string) error {
	usernameVO, err := valueobjects.NewUsername(newUsername)
	if err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	oldUsername := u.username
	u.username = usernameVO
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserUsernameChanged(
		u.id.String(),
		oldUsername.String(),
		newUsername,
		u.updatedAt,
	))

	return nil
}

// ChangePassword changes the user's password
func (u *User) ChangePassword(newPasswordHash string) error {
	passwordHashVO, err := valueobjects.NewPasswordHash(newPasswordHash)
	if err != nil {
		return fmt.Errorf("invalid password hash: %w", err)
	}

	u.passwordHash = passwordHashVO
	u.updatedAt = time.Now()

	// Reset failed login attempts on password change
	u.securityProfile.FailedLoginAttempts = 0
	u.securityProfile.LastFailedLoginAt = nil
	u.securityProfile.AccountLockedAt = nil
	u.securityProfile.AccountLockedUntil = nil

	// Raise domain event
	u.addEvent(events.NewUserPasswordChanged(
		u.id.String(),
		u.updatedAt,
	))

	return nil
}

// UpdateProfile updates the user's profile information
func (u *User) UpdateProfile(profile *UserProfile) {
	u.profile = profile
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserProfileUpdated(
		u.id.String(),
		u.updatedAt,
	))
}

// Activate activates the user account
func (u *User) Activate() {
	if u.isActive {
		return
	}

	u.isActive = true
	u.updatedAt = time.Now()

	// Reset security profile
	u.securityProfile.FailedLoginAttempts = 0
	u.securityProfile.LastFailedLoginAt = nil
	u.securityProfile.AccountLockedAt = nil
	u.securityProfile.AccountLockedUntil = nil

	// Raise domain event
	u.addEvent(events.NewUserActivated(
		u.id.String(),
		u.updatedAt,
	))
}

// Deactivate deactivates the user account
func (u *User) Deactivate() {
	if !u.isActive {
		return
	}

	u.isActive = false
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserDeactivated(
		u.id.String(),
		u.updatedAt,
	))
}

// PromoteToAdmin promotes the user to admin
func (u *User) PromoteToAdmin() {
	if u.isAdmin {
		return
	}

	u.isAdmin = true
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserPromotedToAdmin(
		u.id.String(),
		u.updatedAt,
	))
}

// DemoteFromAdmin demotes the user from admin
func (u *User) DemoteFromAdmin() {
	if !u.isAdmin {
		return
	}

	u.isAdmin = false
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserDemotedFromAdmin(
		u.id.String(),
		u.updatedAt,
	))
}

// RecordSuccessfulLogin records a successful login attempt
func (u *User) RecordSuccessfulLogin(ipAddress string) {
	now := time.Now()
	u.securityProfile.LastLoginAt = &now
	u.securityProfile.LastLoginIP = ipAddress
	u.securityProfile.FailedLoginAttempts = 0
	u.securityProfile.LastFailedLoginAt = nil
	u.securityProfile.AccountLockedAt = nil
	u.securityProfile.AccountLockedUntil = nil
	u.updatedAt = now

	// Raise domain event
	u.addEvent(events.NewUserLoggedIn(
		u.id.String(),
		ipAddress,
		now,
	))
}

// RecordFailedLogin records a failed login attempt
func (u *User) RecordFailedLogin(ipAddress string, maxAttempts int, lockoutDuration time.Duration) {
	now := time.Now()
	u.securityProfile.FailedLoginAttempts++
	u.securityProfile.LastFailedLoginAt = &now
	u.updatedAt = now

	// Check if account should be locked
	if u.securityProfile.FailedLoginAttempts >= maxAttempts {
		u.securityProfile.AccountLockedAt = &now
		lockedUntil := now.Add(lockoutDuration)
		u.securityProfile.AccountLockedUntil = &lockedUntil

		// Raise account locked event
		u.addEvent(events.NewUserAccountLocked(
			u.id.String(),
			u.securityProfile.FailedLoginAttempts,
			lockedUntil,
			now,
		))
	} else {
		// Raise failed login event
		u.addEvent(events.NewUserLoginFailed(
			u.id.String(),
			ipAddress,
			u.securityProfile.FailedLoginAttempts,
			now,
		))
	}
}

// IsAccountLocked checks if the account is currently locked
func (u *User) IsAccountLocked() bool {
	if u.securityProfile.AccountLockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.securityProfile.AccountLockedUntil)
}

// UnlockAccount manually unlocks the account
func (u *User) UnlockAccount() {
	if !u.IsAccountLocked() {
		return
	}

	u.securityProfile.AccountLockedAt = nil
	u.securityProfile.AccountLockedUntil = nil
	u.securityProfile.FailedLoginAttempts = 0
	u.securityProfile.LastFailedLoginAt = nil
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserAccountUnlocked(
		u.id.String(),
		u.updatedAt,
	))
}

// EnableMFA enables multi-factor authentication
func (u *User) EnableMFA(secret string) {
	if u.securityProfile.MFAEnabled {
		return
	}

	u.securityProfile.MFAEnabled = true
	u.securityProfile.MFASecrets = append(u.securityProfile.MFASecrets, secret)
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserMFAEnabled(
		u.id.String(),
		u.updatedAt,
	))
}

// DisableMFA disables multi-factor authentication
func (u *User) DisableMFA() {
	if !u.securityProfile.MFAEnabled {
		return
	}

	u.securityProfile.MFAEnabled = false
	u.securityProfile.MFASecrets = make([]string, 0)
	u.updatedAt = time.Now()

	// Raise domain event
	u.addEvent(events.NewUserMFADisabled(
		u.id.String(),
		u.updatedAt,
	))
}

// CanPerformAction checks if the user can perform a specific action
func (u *User) CanPerformAction(action string) bool {
	if !u.isActive {
		return false
	}

	if u.IsAccountLocked() {
		return false
	}

	// Additional business rules can be added here
	return true
}

// ClearEvents clears all domain events (called after events are published)
func (u *User) ClearEvents() {
	u.events = make([]events.DomainEvent, 0)
}

// Private methods

func (u *User) addEvent(event events.DomainEvent) {
	u.events = append(u.events, event)
}

// Validation methods

// Validate performs domain validation on the user entity
func (u *User) Validate() error {
	if u.id.IsEmpty() {
		return fmt.Errorf("user ID cannot be empty")
	}

	if err := u.email.Validate(); err != nil {
		return fmt.Errorf("invalid email: %w", err)
	}

	if err := u.username.Validate(); err != nil {
		return fmt.Errorf("invalid username: %w", err)
	}

	if err := u.passwordHash.Validate(); err != nil {
		return fmt.Errorf("invalid password hash: %w", err)
	}

	if u.profile == nil {
		return fmt.Errorf("user profile cannot be nil")
	}

	if u.securityProfile == nil {
		return fmt.Errorf("security profile cannot be nil")
	}

	return nil
}