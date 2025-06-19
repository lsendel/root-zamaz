// Package utils provides utility functions for the application.
package utils

import (
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v2"
)

// ParseUintParam parses a uint64 value from a URL parameter.
// It returns the parsed uint64 ID or an error if parsing fails.
// The error message is suitable for a BadRequest response.
func ParseUintParam(c *fiber.Ctx, paramName string) (uint64, error) {
	idStr := c.Params(paramName)
	if idStr == "" {
		return 0, fmt.Errorf("%s parameter is missing", paramName)
	}
	id, err := strconv.ParseUint(idStr, 10, 32) // Using 32 here as most IDs seem to be uint
	if err != nil {
		return 0, fmt.Errorf("invalid %s: must be a valid unsigned integer", paramName)
	}
	return id, nil
}
