// Package common provides shared utilities for HTTP handlers
package common

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"strconv"
)

// ParseUintParam parses a URL parameter as uint with standardized error handling
func ParseUintParam(c *fiber.Ctx, paramName, displayName string) (uint, error) {
	paramStr := c.Params(paramName)
	if paramStr == "" {
		return 0, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": fmt.Sprintf("Missing %s parameter", displayName),
		})
	}

	id, err := strconv.ParseUint(paramStr, 10, 32)
	if err != nil {
		return 0, c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": fmt.Sprintf("Invalid %s", displayName),
		})
	}

	return uint(id), nil
}

// ParseOptionalUintParam parses an optional URL parameter
func ParseOptionalUintParam(c *fiber.Ctx, paramName string) (uint, bool) {
	paramStr := c.Params(paramName)
	if paramStr == "" {
		return 0, false
	}

	id, err := strconv.ParseUint(paramStr, 10, 32)
	if err != nil {
		return 0, false
	}

	return uint(id), true
}

// ParseStringParam parses a string parameter with validation
func ParseStringParam(c *fiber.Ctx, paramName, displayName string) (string, error) {
	paramStr := c.Params(paramName)
	if paramStr == "" {
		return "", c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "Bad Request",
			"message": fmt.Sprintf("Missing %s parameter", displayName),
		})
	}
	return paramStr, nil
}

// ParseQueryParam parses a query parameter with default value
func ParseQueryParam(c *fiber.Ctx, paramName, defaultValue string) string {
	value := c.Query(paramName, defaultValue)
	return value
}

// ParseIntQueryParam parses an integer query parameter with default value
func ParseIntQueryParam(c *fiber.Ctx, paramName string, defaultValue int) (int, error) {
	valueStr := c.Query(paramName)
	if valueStr == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue, fmt.Errorf("invalid %s parameter", paramName)
	}

	return value, nil
}
