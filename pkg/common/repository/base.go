package repository

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"github.com/lsendel/root-zamaz/pkg/common/errors"
)

// PaginationParams represents pagination parameters
type PaginationParams struct {
	Page     int                    `json:"page" validate:"min=1"`
	Limit    int                    `json:"limit" validate:"min=1,max=100"`
	Sort     string                 `json:"sort"`
	Order    string                 `json:"order" validate:"oneof=asc desc"`
	Filters  map[string]interface{} `json:"filters"`
}

// PaginatedResult represents a paginated result set
type PaginatedResult[T any] struct {
	Data       []T   `json:"data"`
	Total      int64 `json:"total"`
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalPages int   `json:"total_pages"`
}

// BaseRepository provides common database operations
type BaseRepository[T any] struct {
	db           *gorm.DB
	errorHandler *errors.Handler
	tableName    string
}

// NewBaseRepository creates a new base repository
func NewBaseRepository[T any](db *gorm.DB, errorHandler *errors.Handler, tableName string) *BaseRepository[T] {
	return &BaseRepository[T]{
		db:           db,
		errorHandler: errorHandler,
		tableName:    tableName,
	}
}

// Create inserts a new entity
func (r *BaseRepository[T]) Create(ctx context.Context, entity *T) error {
	if err := r.db.WithContext(ctx).Create(entity).Error; err != nil {
		return errors.NewDatabaseError("create", r.tableName, err)
	}
	return nil
}

// GetByID retrieves an entity by ID with optional preloads
func (r *BaseRepository[T]) GetByID(ctx context.Context, id string, preloads ...string) (*T, error) {
	var entity T
	
	query := r.db.WithContext(ctx)
	for _, preload := range preloads {
		query = query.Preload(preload)
	}
	
	err := query.First(&entity, "id = ?", id).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError(r.tableName)
		}
		return nil, errors.NewDatabaseError("get_by_id", r.tableName, err)
	}
	
	return &entity, nil
}

// GetByField retrieves an entity by a specific field
func (r *BaseRepository[T]) GetByField(ctx context.Context, field, value string, preloads ...string) (*T, error) {
	var entity T
	
	query := r.db.WithContext(ctx)
	for _, preload := range preloads {
		query = query.Preload(preload)
	}
	
	err := query.Where(fmt.Sprintf("%s = ?", field), value).First(&entity).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, errors.NewNotFoundError(r.tableName)
		}
		return nil, errors.NewDatabaseError("get_by_field", r.tableName, err)
	}
	
	return &entity, nil
}

// Update updates an entity by ID
func (r *BaseRepository[T]) Update(ctx context.Context, id string, updates map[string]interface{}) error {
	// Add updated_at timestamp
	updates["updated_at"] = time.Now()
	
	result := r.db.WithContext(ctx).Model(new(T)).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		return errors.NewDatabaseError("update", r.tableName, result.Error)
	}
	
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError(r.tableName)
	}
	
	return nil
}

// SoftDelete performs a soft delete on an entity
func (r *BaseRepository[T]) SoftDelete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(new(T))
	if result.Error != nil {
		return errors.NewDatabaseError("soft_delete", r.tableName, result.Error)
	}
	
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError(r.tableName)
	}
	
	return nil
}

// HardDelete performs a hard delete on an entity
func (r *BaseRepository[T]) HardDelete(ctx context.Context, id string) error {
	result := r.db.WithContext(ctx).Unscoped().Where("id = ?", id).Delete(new(T))
	if result.Error != nil {
		return errors.NewDatabaseError("hard_delete", r.tableName, result.Error)
	}
	
	if result.RowsAffected == 0 {
		return errors.NewNotFoundError(r.tableName)
	}
	
	return nil
}

// List retrieves entities with pagination and filtering
func (r *BaseRepository[T]) List(ctx context.Context, params PaginationParams, preloads ...string) (*PaginatedResult[T], error) {
	var entities []T
	var total int64
	
	// Build base query
	query := r.db.WithContext(ctx).Model(new(T))
	
	// Apply filters
	if params.Filters != nil {
		for field, value := range params.Filters {
			query = query.Where(fmt.Sprintf("%s = ?", field), value)
		}
	}
	
	// Count total records
	if err := query.Count(&total).Error; err != nil {
		return nil, errors.NewDatabaseError("count", r.tableName, err)
	}
	
	// Apply preloads
	for _, preload := range preloads {
		query = query.Preload(preload)
	}
	
	// Apply sorting
	if params.Sort != "" {
		order := "ASC"
		if params.Order != "" {
			order = params.Order
		}
		query = query.Order(fmt.Sprintf("%s %s", params.Sort, order))
	}
	
	// Apply pagination
	offset := (params.Page - 1) * params.Limit
	query = query.Offset(offset).Limit(params.Limit)
	
	// Execute query
	if err := query.Find(&entities).Error; err != nil {
		return nil, errors.NewDatabaseError("list", r.tableName, err)
	}
	
	// Calculate total pages
	totalPages := int((total + int64(params.Limit) - 1) / int64(params.Limit))
	
	return &PaginatedResult[T]{
		Data:       entities,
		Total:      total,
		Page:       params.Page,
		Limit:      params.Limit,
		TotalPages: totalPages,
	}, nil
}

// Exists checks if an entity exists by ID
func (r *BaseRepository[T]) Exists(ctx context.Context, id string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(new(T)).Where("id = ?", id).Count(&count).Error
	if err != nil {
		return false, errors.NewDatabaseError("exists", r.tableName, err)
	}
	
	return count > 0, nil
}

// ExistsByField checks if an entity exists by a specific field
func (r *BaseRepository[T]) ExistsByField(ctx context.Context, field, value string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(new(T)).Where(fmt.Sprintf("%s = ?", field), value).Count(&count).Error
	if err != nil {
		return false, errors.NewDatabaseError("exists_by_field", r.tableName, err)
	}
	
	return count > 0, nil
}

// BatchCreate inserts multiple entities in a single transaction
func (r *BaseRepository[T]) BatchCreate(ctx context.Context, entities []T, batchSize int) error {
	if len(entities) == 0 {
		return nil
	}
	
	if batchSize <= 0 {
		batchSize = 100 // Default batch size
	}
	
	for i := 0; i < len(entities); i += batchSize {
		end := i + batchSize
		if end > len(entities) {
			end = len(entities)
		}
		
		batch := entities[i:end]
		if err := r.db.WithContext(ctx).Create(&batch).Error; err != nil {
			return errors.NewDatabaseError("batch_create", r.tableName, err)
		}
	}
	
	return nil
}

// Transaction executes a function within a database transaction
func (r *BaseRepository[T]) Transaction(ctx context.Context, fn func(*gorm.DB) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := fn(tx); err != nil {
			return errors.NewDatabaseError("transaction", r.tableName, err)
		}
		return nil
	})
}