// Package common provides shared middleware utilities testing
package common

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenExtractor(t *testing.T) {
	extractor := NewTokenExtractor("Authorization")

	t.Run("extract from authorization header", func(t *testing.T) {
		tests := []struct {
			name        string
			headerValue string
			expected    string
		}{
			{
				name:        "bearer token",
				headerValue: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				expected:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			},
			{
				name:        "token without bearer prefix",
				headerValue: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				expected:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			},
			{
				name:        "empty header",
				headerValue: "",
				expected:    "",
			},
			{
				name:        "bearer with extra spaces",
				headerValue: "Bearer  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ",
				expected:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := extractor.ExtractFromHeader(tt.headerValue)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("extract from query parameter", func(t *testing.T) {
		tests := []struct {
			name     string
			query    string
			expected string
		}{
			{
				name:     "valid token",
				query:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			},
			{
				name:     "token with spaces",
				query:    "  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ",
				expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			},
			{
				name:     "empty query",
				query:    "",
				expected: "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := extractor.ExtractFromQueryParam(tt.query)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("extract from cookie", func(t *testing.T) {
		tests := []struct {
			name     string
			cookie   string
			expected string
		}{
			{
				name:     "valid token",
				cookie:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			},
			{
				name:     "token with spaces",
				cookie:   "  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ",
				expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			},
			{
				name:     "empty cookie",
				cookie:   "",
				expected: "",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := extractor.ExtractFromCookie(tt.cookie)
				assert.Equal(t, tt.expected, result)
			})
		}
	})

	t.Run("extract from HTTP request", func(t *testing.T) {
		testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

		t.Run("from authorization header", func(t *testing.T) {
			req := &http.Request{
				Header: http.Header{
					"Authorization": []string{"Bearer " + testToken},
				},
			}

			result := extractor.ExtractFromHTTPRequest(req)
			assert.Equal(t, testToken, result)
		})

		t.Run("from query parameter", func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{
					RawQuery: "token=" + testToken,
				},
				Header: http.Header{},
			}

			result := extractor.ExtractFromHTTPRequest(req)
			assert.Equal(t, testToken, result)
		})

		t.Run("from cookie", func(t *testing.T) {
			req := &http.Request{
				Header: http.Header{
					"Cookie": []string{"token=" + testToken},
				},
			}

			result := extractor.ExtractFromHTTPRequest(req)
			assert.Equal(t, testToken, result)
		})

		t.Run("precedence order", func(t *testing.T) {
			headerToken := "header-token"
			queryToken := "query-token"
			cookieToken := "cookie-token"

			req := &http.Request{
				URL: &url.URL{
					RawQuery: "token=" + queryToken,
				},
				Header: http.Header{
					"Authorization": []string{"Bearer " + headerToken},
					"Cookie":        []string{"token=" + cookieToken},
				},
			}

			result := extractor.ExtractFromHTTPRequest(req)
			assert.Equal(t, headerToken, result, "Header should have highest precedence")
		})

		t.Run("fallback to query when header empty", func(t *testing.T) {
			queryToken := "query-token"
			cookieToken := "cookie-token"

			req := &http.Request{
				URL: &url.URL{
					RawQuery: "token=" + queryToken,
				},
				Header: http.Header{
					"Cookie": []string{"token=" + cookieToken},
				},
			}

			result := extractor.ExtractFromHTTPRequest(req)
			assert.Equal(t, queryToken, result, "Query should be used when header is empty")
		})

		t.Run("fallback to cookie when header and query empty", func(t *testing.T) {
			cookieToken := "cookie-token"

			req := &http.Request{
				URL:    &url.URL{},
				Header: http.Header{
					"Cookie": []string{"token=" + cookieToken},
				},
			}

			result := extractor.ExtractFromHTTPRequest(req)
			assert.Equal(t, cookieToken, result, "Cookie should be used when header and query are empty")
		})

		t.Run("no token found", func(t *testing.T) {
			req := &http.Request{
				URL:    &url.URL{},
				Header: http.Header{},
			}

			result := extractor.ExtractFromHTTPRequest(req)
			assert.Empty(t, result)
		})
	})
}

func TestFrameworkTokenExtractor(t *testing.T) {
	extractor := NewFrameworkExtractor("Authorization")

	t.Run("extract from gin context", func(t *testing.T) {
		testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

		// Mock Gin context
		mockGinContext := &MockGinContext{
			headers: map[string]string{
				"Authorization": "Bearer " + testToken,
			},
			queries: map[string]string{},
			cookies: map[string]string{},
		}

		result := extractor.ExtractFromGinContext(mockGinContext)
		assert.Equal(t, testToken, result)
	})

	t.Run("extract from echo context", func(t *testing.T) {
		testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

		req := &http.Request{
			Header: http.Header{
				"Authorization": []string{"Bearer " + testToken},
			},
		}

		mockEchoContext := &MockEchoContext{
			request: req,
		}

		result := extractor.ExtractFromEchoContext(mockEchoContext)
		assert.Equal(t, testToken, result)
	})

	t.Run("extract from fiber context", func(t *testing.T) {
		testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

		mockFiberContext := &MockFiberContext{
			headers: map[string]string{
				"Authorization": "Bearer " + testToken,
			},
			queries: map[string]string{},
			cookies: map[string]string{},
		}

		result := extractor.ExtractFromFiberContext(mockFiberContext)
		assert.Equal(t, testToken, result)
	})

	t.Run("extract from grpc metadata", func(t *testing.T) {
		testToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

		mockMetadata := &MockGRPCMetadata{
			data: map[string][]string{
				"authorization": {"Bearer " + testToken},
			},
		}

		result := extractor.ExtractFromGRPCMetadata(mockMetadata)
		assert.Equal(t, testToken, result)
	})

	t.Run("handle invalid context types", func(t *testing.T) {
		// Test with incompatible context types
		result := extractor.ExtractFromGinContext("invalid-context")
		assert.Empty(t, result)

		result = extractor.ExtractFromEchoContext(123)
		assert.Empty(t, result)

		result = extractor.ExtractFromFiberContext(struct{}{})
		assert.Empty(t, result)

		result = extractor.ExtractFromGRPCMetadata(nil)
		assert.Empty(t, result)
	})
}

func TestTokenExtractorWithCustomHeader(t *testing.T) {
	customExtractor := NewTokenExtractor("X-API-Key")

	req := &http.Request{
		Header: http.Header{
			"X-API-Key":     []string{"custom-api-key"},
			"Authorization": []string{"Bearer should-not-be-used"},
		},
	}

	result := customExtractor.ExtractFromHTTPRequest(req)
	assert.Equal(t, "custom-api-key", result)
}

// Mock implementations for testing

type MockGinContext struct {
	headers map[string]string
	queries map[string]string
	cookies map[string]string
}

func (m *MockGinContext) GetHeader(key string) string {
	return m.headers[key]
}

func (m *MockGinContext) Query(key string) string {
	return m.queries[key]
}

func (m *MockGinContext) Cookie(key string) (string, error) {
	if value, exists := m.cookies[key]; exists {
		return value, nil
	}
	return "", http.ErrNoCookie
}

type MockEchoContext struct {
	request *http.Request
}

func (m *MockEchoContext) Request() *http.Request {
	return m.request
}

type MockFiberContext struct {
	headers map[string]string
	queries map[string]string
	cookies map[string]string
}

func (m *MockFiberContext) Get(key string) string {
	return m.headers[key]
}

func (m *MockFiberContext) Query(key string) string {
	return m.queries[key]
}

func (m *MockFiberContext) Cookies(key string) string {
	return m.cookies[key]
}

type MockGRPCMetadata struct {
	data map[string][]string
}

func (m *MockGRPCMetadata) Get(key string) []string {
	return m.data[key]
}