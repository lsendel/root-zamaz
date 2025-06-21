// Package common provides shared utilities for HTTP handlers
package common

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"mvp.local/pkg/errors"
)

// HandleDatabaseError provides standardized database error handling
func HandleDatabaseError(c *fiber.Ctx, err error, resourceName string) error {
	if err == gorm.ErrRecordNotFound {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error":   "Not Found",
			"message": fmt.Sprintf("%s not found", resourceName),
		})
	}

	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error":   "Internal Server Error",
		"message": "Database error",
	})
}

// FindByID provides standardized record retrieval with error handling
func FindByID[T any](db *gorm.DB, id uint, dest *T, resourceName string) error {
	if err := db.First(dest, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return errors.NotFound(fmt.Sprintf("%s not found", resourceName))
		}
		return errors.Internal("Database error")
	}
	return nil
}

// SaveRecord provides standardized record saving with error handling
func SaveRecord[T any](db *gorm.DB, record *T, resourceName string) error {
	if err := db.Save(record).Error; err != nil {
		return errors.Internal(fmt.Sprintf("Failed to save %s", resourceName))
	}
	return nil
}

// CreateRecord provides standardized record creation with error handling
func CreateRecord[T any](db *gorm.DB, record *T, resourceName string) error {
	if err := db.Create(record).Error; err != nil {
		return errors.Internal(fmt.Sprintf("Failed to create %s", resourceName))
	}
	return nil
}

// DeleteRecord provides standardized record deletion with error handling
func DeleteRecord[T any](db *gorm.DB, record *T, resourceName string) error {
	if err := db.Delete(record).Error; err != nil {
		return errors.Internal(fmt.Sprintf("Failed to delete %s", resourceName))
	}
	return nil
}

// CheckRecordExists checks if a record exists by a condition
func CheckRecordExists[T any](db *gorm.DB, condition string, args ...interface{}) (bool, error) {
	var record T
	err := db.Where(condition, args...).First(&record).Error
	if err == gorm.ErrRecordNotFound {
		return false, nil
	}
	if err != nil {
		return false, errors.Internal("Database error")
	}
	return true, nil
}
