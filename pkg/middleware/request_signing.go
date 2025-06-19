package middleware

import (
	"github.com/gofiber/fiber/v2"

	"mvp.local/pkg/errors"
	"mvp.local/pkg/security"
)

// RequestSigningMiddleware validates request signatures.
func RequestSigningMiddleware(validator *security.SignatureValidator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if err := validator.Validate(c.Request()); err != nil {
			return errors.Unauthorized("invalid request signature").WithDetails(err.Error())
		}
		return c.Next()
	}
}
