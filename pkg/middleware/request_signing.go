package middleware

import (
	"net/http"
	"net/url"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"

	"mvp.local/pkg/errors"
	"mvp.local/pkg/security"
)

// RequestSigningMiddleware validates request signatures.
func RequestSigningMiddleware(validator *security.SignatureValidator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Convert fasthttp.Request to http.Request for the validator
		httpReq, err := convertFastHTTPToHTTP(c.Request())
		if err != nil {
			return errors.Internal("failed to convert request for signature validation").WithDetails(err.Error())
		}

		if err := validator.Validate(httpReq); err != nil {
			return errors.Unauthorized("invalid request signature").WithDetails(err.Error())
		}
		return c.Next()
	}
}

// convertFastHTTPToHTTP converts a fasthttp.Request to http.Request
func convertFastHTTPToHTTP(fhReq *fasthttp.Request) (*http.Request, error) {
	// Parse URL
	uri := fhReq.URI()
	reqURL, err := url.Parse(string(uri.FullURI()))
	if err != nil {
		return nil, err
	}

	// Create http.Request
	httpReq := &http.Request{
		Method: string(fhReq.Header.Method()),
		URL:    reqURL,
		Header: make(http.Header),
	}

	// Copy headers
	fhReq.Header.VisitAll(func(key, value []byte) {
		httpReq.Header.Add(string(key), string(value))
	})

	// Set Host
	if host := fhReq.Header.Host(); len(host) > 0 {
		httpReq.Host = string(host)
	}

	return httpReq, nil
}
