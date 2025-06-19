package handlers

import (
	"context"
	"fmt"
	"math"

	"mvp.local/pkg/application/queries"
	"mvp.local/pkg/domain/entities"
	"mvp.local/pkg/domain/repositories"
	"mvp.local/pkg/observability"
)

// UserQueryHandler handles user-related queries
type UserQueryHandler struct {
	userRepo repositories.UserRepository
	obs      *observability.Observability
}

// NewUserQueryHandler creates a new user query handler
func NewUserQueryHandler(
	userRepo repositories.UserRepository,
	obs *observability.Observability,
) *UserQueryHandler {
	return &UserQueryHandler{
		userRepo: userRepo,
		obs:      obs,
	}
}

// GetUser handles the GetUserQuery
func (h *UserQueryHandler) GetUser(ctx context.Context, query queries.GetUserQuery) (*queries.UserView, error) {
	logger := h.obs.Logger.With().
		Str("query", "GetUser").
		Str("user_id", query.UserID).
		Logger()

	logger.Debug().Msg("Processing GetUser query")

	user, err := h.userRepo.GetByID(ctx, query.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	userView := h.mapUserToView(user)

	logger.Debug().Msg("GetUser query completed successfully")
	return userView, nil
}

// GetUserByEmail handles the GetUserByEmailQuery
func (h *UserQueryHandler) GetUserByEmail(ctx context.Context, query queries.GetUserByEmailQuery) (*queries.UserView, error) {
	logger := h.obs.Logger.With().
		Str("query", "GetUserByEmail").
		Str("email", query.Email).
		Logger()

	logger.Debug().Msg("Processing GetUserByEmail query")

	user, err := h.userRepo.GetByEmail(ctx, query.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	userView := h.mapUserToView(user)

	logger.Debug().Msg("GetUserByEmail query completed successfully")
	return userView, nil
}

// GetUserByUsername handles the GetUserByUsernameQuery
func (h *UserQueryHandler) GetUserByUsername(ctx context.Context, query queries.GetUserByUsernameQuery) (*queries.UserView, error) {
	logger := h.obs.Logger.With().
		Str("query", "GetUserByUsername").
		Str("username", query.Username).
		Logger()

	logger.Debug().Msg("Processing GetUserByUsername query")

	user, err := h.userRepo.GetByUsername(ctx, query.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}

	userView := h.mapUserToView(user)

	logger.Debug().Msg("GetUserByUsername query completed successfully")
	return userView, nil
}

// ListUsers handles the ListUsersQuery
func (h *UserQueryHandler) ListUsers(ctx context.Context, query queries.ListUsersQuery) (*queries.UserListView, error) {
	logger := h.obs.Logger.With().
		Str("query", "ListUsers").
		Int("page", query.Page).
		Int("page_size", query.PageSize).
		Str("search", query.Search).
		Logger()

	logger.Debug().Msg("Processing ListUsers query")

	// Set default values
	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 {
		query.PageSize = 20
	}
	if query.PageSize > 100 {
		query.PageSize = 100 // Limit max page size
	}

	// Build criteria
	criteria := repositories.ListUsersCriteria{
		Page:     query.Page,
		PageSize: query.PageSize,
		Search:   query.Search,
		IsActive: query.IsActive,
		IsAdmin:  query.IsAdmin,
		SortBy:   query.SortBy,
		SortDesc: query.SortDesc,
	}

	// Get users
	result, err := h.userRepo.List(ctx, criteria)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Map to view models
	userViews := make([]queries.UserView, len(result.Users))
	for i, user := range result.Users {
		userViews[i] = *h.mapUserToView(user)
	}

	// Calculate total pages
	totalPages := int(math.Ceil(float64(result.Total) / float64(query.PageSize)))

	userListView := &queries.UserListView{
		Users:      userViews,
		Total:      result.Total,
		Page:       query.Page,
		PageSize:   query.PageSize,
		TotalPages: totalPages,
	}

	logger.Debug().
		Int64("total", result.Total).
		Int("returned", len(userViews)).
		Msg("ListUsers query completed successfully")

	return userListView, nil
}

// GetUserSessions handles the GetUserSessionsQuery
func (h *UserQueryHandler) GetUserSessions(ctx context.Context, query queries.GetUserSessionsQuery) (*queries.SessionListView, error) {
	// This is a placeholder implementation
	// In a real implementation, you would have a SessionRepository
	logger := h.obs.Logger.With().
		Str("query", "GetUserSessions").
		Str("user_id", query.UserID).
		Logger()

	logger.Debug().Msg("Processing GetUserSessions query")

	// For now, return empty list
	// TODO: Implement when SessionRepository is available
	sessionListView := &queries.SessionListView{
		Sessions:   []queries.SessionView{},
		Total:      0,
		Page:       query.Page,
		PageSize:   query.PageSize,
		TotalPages: 0,
	}

	logger.Debug().Msg("GetUserSessions query completed successfully")
	return sessionListView, nil
}

// GetUserAuditLog handles the GetUserAuditLogQuery
func (h *UserQueryHandler) GetUserAuditLog(ctx context.Context, query queries.GetUserAuditLogQuery) (*queries.AuditLogView, error) {
	// This is a placeholder implementation
	// In a real implementation, you would have an AuditLogRepository
	logger := h.obs.Logger.With().
		Str("query", "GetUserAuditLog").
		Str("user_id", query.UserID).
		Logger()

	logger.Debug().Msg("Processing GetUserAuditLog query")

	// For now, return empty list
	// TODO: Implement when AuditLogRepository is available
	auditLogView := &queries.AuditLogView{
		Entries:    []queries.AuditLogEntry{},
		Total:      0,
		Page:       query.Page,
		PageSize:   query.PageSize,
		TotalPages: 0,
	}

	logger.Debug().Msg("GetUserAuditLog query completed successfully")
	return auditLogView, nil
}

// mapUserToView maps a user entity to a user view model
func (h *UserQueryHandler) mapUserToView(user *entities.User) *queries.UserView {
	userView := &queries.UserView{
		ID:        user.ID().String(),
		Email:     user.Email().String(),
		Username:  user.Username().String(),
		IsActive:  user.IsActive(),
		IsAdmin:   user.IsAdmin(),
		CreatedAt: user.CreatedAt(),
		UpdatedAt: user.UpdatedAt(),
	}

	// Map profile information
	if profile := user.Profile(); profile != nil {
		userView.FirstName = profile.FirstName
		userView.LastName = profile.LastName
	}

	// Map security profile information
	if securityProfile := user.SecurityProfile(); securityProfile != nil {
		userView.LastLoginAt = securityProfile.LastLoginAt
		userView.LastLoginIP = securityProfile.LastLoginIP
		userView.FailedLoginAttempts = securityProfile.FailedLoginAttempts
		userView.AccountLockedUntil = securityProfile.AccountLockedUntil
		userView.MFAEnabled = securityProfile.MFAEnabled
	}

	return userView
}
