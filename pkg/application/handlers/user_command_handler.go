// Package handlers provides command and query handlers for the application layer.
package handlers

import (
	"context"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"mvp.local/pkg/application/commands"
	"mvp.local/pkg/domain/entities"
	"mvp.local/pkg/domain/events"
	"mvp.local/pkg/domain/repositories"
	"mvp.local/pkg/observability"
)

// UserCommandHandler handles user-related commands
type UserCommandHandler struct {
	userRepo   repositories.UserRepository
	eventBus   EventBus
	obs        *observability.Observability
	userFactory *entities.UserFactory
}

// EventBus interface for publishing domain events
type EventBus interface {
	Publish(ctx context.Context, events []events.DomainEvent) error
}

// NewUserCommandHandler creates a new user command handler
func NewUserCommandHandler(
	userRepo repositories.UserRepository,
	eventBus EventBus,
	obs *observability.Observability,
) *UserCommandHandler {
	return &UserCommandHandler{
		userRepo:    userRepo,
		eventBus:    eventBus,
		obs:         obs,
		userFactory: entities.NewUserFactory(),
	}
}

// CreateUser handles the CreateUserCommand
func (h *UserCommandHandler) CreateUser(ctx context.Context, cmd commands.CreateUserCommand) (*commands.CreateUserResult, error) {
	logger := h.obs.Logger.With().
		Str("command", "CreateUser").
		Str("email", cmd.Email).
		Str("username", cmd.Username).
		Logger()

	logger.Info().Msg("Processing CreateUser command")

	// Check if user already exists
	existingUser, err := h.userRepo.GetByEmail(ctx, cmd.Email)
	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", cmd.Email)
	}

	existingUser, err = h.userRepo.GetByUsername(ctx, cmd.Username)
	if err == nil && existingUser != nil {
		return nil, fmt.Errorf("user with username %s already exists", cmd.Username)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cmd.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user profile
	profile := &entities.UserProfile{
		FirstName: cmd.FirstName,
		LastName:  cmd.LastName,
	}

	// Create user entity
	user, err := h.userFactory.CreateUser(
		cmd.Email,
		cmd.Username,
		string(hashedPassword),
		profile,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user entity: %w", err)
	}

	// Save user
	if err := h.userRepo.Save(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	// Publish domain events
	if err := h.eventBus.Publish(ctx, user.Events()); err != nil {
		logger.Error().Err(err).Msg("Failed to publish domain events")
		// Don't fail the command, just log the error
	}

	// Clear events after publishing
	user.ClearEvents()

	logger.Info().
		Str("user_id", user.ID().String()).
		Msg("User created successfully")

	return &commands.CreateUserResult{
		UserID:    user.ID().String(),
		Email:     user.Email().String(),
		Username:  user.Username().String(),
		CreatedAt: user.CreatedAt(),
	}, nil
}

// UpdateUser handles the UpdateUserCommand
func (h *UserCommandHandler) UpdateUser(ctx context.Context, cmd commands.UpdateUserCommand) error {
	logger := h.obs.Logger.With().
		Str("command", "UpdateUser").
		Str("user_id", cmd.UserID).
		Logger()

	logger.Info().Msg("Processing UpdateUser command")

	// Get user
	user, err := h.userRepo.GetByID(ctx, cmd.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Update email if provided
	if cmd.Email != nil {
		if err := user.ChangeEmail(*cmd.Email); err != nil {
			return fmt.Errorf("failed to change email: %w", err)
		}
	}

	// Update username if provided
	if cmd.Username != nil {
		if err := user.ChangeUsername(*cmd.Username); err != nil {
			return fmt.Errorf("failed to change username: %w", err)
		}
	}

	// Update profile if provided
	if cmd.FirstName != nil || cmd.LastName != nil {
		profile := user.Profile()
		if profile == nil {
			profile = &entities.UserProfile{}
		}
		if cmd.FirstName != nil {
			profile.FirstName = *cmd.FirstName
		}
		if cmd.LastName != nil {
			profile.LastName = *cmd.LastName
		}
		user.UpdateProfile(profile)
	}

	// Save user
	if err := h.userRepo.Save(ctx, user); err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	// Publish domain events
	if err := h.eventBus.Publish(ctx, user.Events()); err != nil {
		logger.Error().Err(err).Msg("Failed to publish domain events")
	}

	// Clear events after publishing
	user.ClearEvents()

	logger.Info().Msg("User updated successfully")
	return nil
}

// ChangePassword handles the ChangePasswordCommand
func (h *UserCommandHandler) ChangePassword(ctx context.Context, cmd commands.ChangePasswordCommand) error {
	logger := h.obs.Logger.With().
		Str("command", "ChangePassword").
		Str("user_id", cmd.UserID).
		Logger()

	logger.Info().Msg("Processing ChangePassword command")

	// Get user
	user, err := h.userRepo.GetByID(ctx, cmd.UserID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash().String()), []byte(cmd.OldPassword)); err != nil {
		return fmt.Errorf("invalid old password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cmd.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Change password
	if err := user.ChangePassword(string(hashedPassword)); err != nil {
		return fmt.Errorf("failed to change password: %w", err)
	}

	// Save user
	if err := h.userRepo.Save(ctx, user); err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	// Publish domain events
	if err := h.eventBus.Publish(ctx, user.Events()); err != nil {
		logger.Error().Err(err).Msg("Failed to publish domain events")
	}

	// Clear events after publishing
	user.ClearEvents()

	logger.Info().Msg("Password changed successfully")
	return nil
}

// ActivateUser handles the ActivateUserCommand
func (h *UserCommandHandler) ActivateUser(ctx context.Context, cmd commands.ActivateUserCommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "ActivateUser", func(user *entities.User) {
		user.Activate()
	})
}

// DeactivateUser handles the DeactivateUserCommand
func (h *UserCommandHandler) DeactivateUser(ctx context.Context, cmd commands.DeactivateUserCommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "DeactivateUser", func(user *entities.User) {
		user.Deactivate()
	})
}

// PromoteToAdmin handles the PromoteToAdminCommand
func (h *UserCommandHandler) PromoteToAdmin(ctx context.Context, cmd commands.PromoteToAdminCommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "PromoteToAdmin", func(user *entities.User) {
		user.PromoteToAdmin()
	})
}

// DemoteFromAdmin handles the DemoteFromAdminCommand
func (h *UserCommandHandler) DemoteFromAdmin(ctx context.Context, cmd commands.DemoteFromAdminCommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "DemoteFromAdmin", func(user *entities.User) {
		user.DemoteFromAdmin()
	})
}

// RecordLogin handles the RecordLoginCommand
func (h *UserCommandHandler) RecordLogin(ctx context.Context, cmd commands.RecordLoginCommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "RecordLogin", func(user *entities.User) {
		user.RecordSuccessfulLogin(cmd.IPAddress)
	})
}

// RecordFailedLogin handles the RecordFailedLoginCommand
func (h *UserCommandHandler) RecordFailedLogin(ctx context.Context, cmd commands.RecordFailedLoginCommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "RecordFailedLogin", func(user *entities.User) {
		user.RecordFailedLogin(cmd.IPAddress, cmd.MaxAttempts, cmd.LockoutDuration)
	})
}

// UnlockAccount handles the UnlockAccountCommand
func (h *UserCommandHandler) UnlockAccount(ctx context.Context, cmd commands.UnlockAccountCommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "UnlockAccount", func(user *entities.User) {
		user.UnlockAccount()
	})
}

// EnableMFA handles the EnableMFACommand
func (h *UserCommandHandler) EnableMFA(ctx context.Context, cmd commands.EnableMFACommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "EnableMFA", func(user *entities.User) {
		user.EnableMFA(cmd.Secret)
	})
}

// DisableMFA handles the DisableMFACommand
func (h *UserCommandHandler) DisableMFA(ctx context.Context, cmd commands.DisableMFACommand) error {
	return h.updateUserStatus(ctx, cmd.UserID, "DisableMFA", func(user *entities.User) {
		user.DisableMFA()
	})
}

// updateUserStatus is a helper method for status update operations
func (h *UserCommandHandler) updateUserStatus(ctx context.Context, userID, command string, operation func(*entities.User)) error {
	logger := h.obs.Logger.With().
		Str("command", command).
		Str("user_id", userID).
		Logger()

	logger.Info().Msgf("Processing %s command", command)

	// Get user
	user, err := h.userRepo.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return fmt.Errorf("user not found")
	}

	// Apply operation
	operation(user)

	// Save user
	if err := h.userRepo.Save(ctx, user); err != nil {
		return fmt.Errorf("failed to save user: %w", err)
	}

	// Publish domain events
	if err := h.eventBus.Publish(ctx, user.Events()); err != nil {
		logger.Error().Err(err).Msg("Failed to publish domain events")
	}

	// Clear events after publishing
	user.ClearEvents()

	logger.Info().Msgf("%s completed successfully", command)
	return nil
}