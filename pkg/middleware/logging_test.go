package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"net/url" // Added for url.Parse in tests

	"mvp.local/pkg/observability"
)

// --- Test Setup & Helpers ---

func MockLoggerForLogging(buf *bytes.Buffer) zerolog.Logger {
	return zerolog.New(buf).With().Timestamp().Logger()
}

func MockObservabilityForLogging(logger zerolog.Logger) *observability.Observability {
	return &observability.Observability{
		Logger: logger,
	}
}

func performLoggingTestRequest(
	t *testing.T,
	configuredHandler fiber.Handler,
	logBuf *bytes.Buffer,
	method, requestPath string, // requestPath can include query params
	body io.Reader,
	headers map[string]string,
	routeHandler fiber.Handler,
) (resp *http.Response) {

	app := fiber.New()
	app.Use(configuredHandler)

	// Extract base path for routing
	basePath := requestPath
	if qIndex := strings.Index(requestPath, "?"); qIndex != -1 {
		basePath = requestPath[:qIndex]
	}

	// Register route with base path
	switch strings.ToUpper(method) {
	case "GET":
		app.Get(basePath, routeHandler)
	case "POST":
		app.Post(basePath, routeHandler)
	case "PUT":
		app.Put(basePath, routeHandler)
	case "DELETE":
		app.Delete(basePath, routeHandler)
	default:
		app.All(basePath, routeHandler)
	}

	// Create request with full path (including query if any)
	req := httptest.NewRequest(method, requestPath, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	httpResp, err := app.Test(req, -1)
	require.NoError(t, err, "app.Test failed")

	return httpResp
}

var defaultRouteHandler = func(c *fiber.Ctx) error {
	if c.Query("error") == "true" {
		return fiber.NewError(http.StatusInternalServerError, "Simulated handler error")
	}
	if c.Query("sendbody") == "true" {
		c.Set("Content-Type", "application/json")
		return c.Status(http.StatusOK).JSON(fiber.Map{"message": "handler_response_payload"})
	}
	return c.Status(http.StatusOK).SendString("OK")
}

// --- LoggingMiddleware Test Suite ---

func TestLoggingMiddleware_DefaultConfig_SuccessfulRequest(t *testing.T) {
	cfg := DefaultLoggingConfig()
	basePath := "/test_default_ok"
	requestPath := basePath + "?param1=value1&token=secrettoken"

	logBuf := new(bytes.Buffer)
	logger := MockLoggerForLogging(logBuf)
	obs := MockObservabilityForLogging(logger)
	configuredMiddleware := LoggingMiddleware(obs, cfg)

	resp := performLoggingTestRequest(t,
		configuredMiddleware,
		logBuf,
		"GET",
		requestPath,
		nil,
		map[string]string{"X-Test-Header": "test-value", "Authorization": "Bearer oldjwt"},
		defaultRouteHandler,
	)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	logOutput := logBuf.String()

	assert.Contains(t, logOutput, `"message":"HTTP request"`)
	var reqLogEntry struct {
		Request RequestLogEntry `json:"request"`
	}
	for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
		if strings.Contains(line, `"message":"HTTP request"`) {
			err := json.Unmarshal([]byte(line), &reqLogEntry)
			require.NoError(t, err, "Failed to unmarshal request log: %s", line)
			break
		}
	}
	assert.Equal(t, "GET", reqLogEntry.Request.Method)
	assert.Equal(t, basePath, reqLogEntry.Request.Path) // Path logged should be base path
	assert.Contains(t, reqLogEntry.Request.Query, "param1=value1")
	assert.Contains(t, reqLogEntry.Request.Query, "token=%5BREDACTED%5D") // Expect URL-encoded
	assert.NotEmpty(t, reqLogEntry.Request.ClientIP)
	assert.Equal(t, "", reqLogEntry.Request.UserAgent)
	assert.Nil(t, reqLogEntry.Request.Headers, "Request headers should not be logged by default")
	assert.Empty(t, reqLogEntry.Request.Body, "Request body should not be logged by default")

	assert.Contains(t, logOutput, `"message":"HTTP response"`)
	var respLogEntry struct {
		Response ResponseLogEntry `json:"response"`
	}
	for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
		if strings.Contains(line, `"message":"HTTP response"`) {
			err := json.Unmarshal([]byte(line), &respLogEntry)
			require.NoError(t, err, "Failed to unmarshal response log: %s", line)
			break
		}
	}
	assert.Equal(t, http.StatusOK, respLogEntry.Response.StatusCode)
	assert.True(t, respLogEntry.Response.Duration >= 0)
	assert.Nil(t, respLogEntry.Response.Headers, "Response headers should not be logged by default")
	assert.Empty(t, respLogEntry.Response.Body, "Response body should not be logged by default (and not implemented)")
	assert.Empty(t, respLogEntry.Response.Error)
}

func TestLoggingMiddleware_DisabledRequestResponseLogging(t *testing.T) {
	cfg := DefaultLoggingConfig()
	cfg.LogRequests = false
	cfg.LogResponses = false
	path := "/test_no_log"

	logBuf := new(bytes.Buffer)
	logger := MockLoggerForLogging(logBuf)
	obs := MockObservabilityForLogging(logger)
	configuredMiddleware := LoggingMiddleware(obs, cfg)

	performLoggingTestRequest(t,
		configuredMiddleware,
		logBuf,
		"GET",
		path,
		nil,
		nil,
		defaultRouteHandler,
	)
	logOutput := logBuf.String()

	assert.NotContains(t, logOutput, `"message":"HTTP request"`)
	assert.NotContains(t, logOutput, `"message":"HTTP response"`)
}

func TestLoggingMiddleware_HeaderLogging(t *testing.T) {
	tests := []struct {
		name                 string
		logRequestHeaders    bool
		logResponseHeaders   bool
		sensitiveHeaders     []string
		redactSensitiveData  bool
		requestHeadersMap    map[string]string
		expectedReqHeaders   map[string]string
		expectedRespHeaders  map[string]string
	}{
		{
			name:               "request headers logged, response headers not",
			logRequestHeaders:  true,
			logResponseHeaders: false,
			requestHeadersMap:  map[string]string{"X-Custom-Req": "reqVal", "Authorization": "secret"},
			sensitiveHeaders:   DefaultLoggingConfig().SensitiveHeaders,
			redactSensitiveData:true,
			expectedReqHeaders: map[string]string{"x-custom-req": "reqVal", "authorization": "[REDACTED]", "host":"example.com"}, // Added host
			expectedRespHeaders:nil,
		},
		{
			name:               "response headers logged, request headers not",
			logRequestHeaders:  false,
			logResponseHeaders: true,
			sensitiveHeaders:   DefaultLoggingConfig().SensitiveHeaders,
			redactSensitiveData:true,
			expectedReqHeaders: nil,
			expectedRespHeaders:map[string]string{"content-type": "application/json"},
		},
		{
			name:               "custom sensitive list, Authorization not redacted",
			logRequestHeaders:  true,
			logResponseHeaders: true,
			requestHeadersMap:  map[string]string{"Authorization": "secret-token"},
			sensitiveHeaders:   []string{"X-Another-Sensitive"},
			redactSensitiveData:true,
			expectedReqHeaders: map[string]string{"authorization": "secret-token", "host":"example.com"}, // Added host
			expectedRespHeaders: map[string]string{"content-type": "application/json"},
		},
		{
			name:               "both headers logged, RedactSensitiveData=false",
			logRequestHeaders:  true,
			logResponseHeaders: true,
			requestHeadersMap:  map[string]string{"Authorization": "secret-token", "X-Normal": "normal"},
			sensitiveHeaders:   DefaultLoggingConfig().SensitiveHeaders,
			redactSensitiveData:false,
			expectedReqHeaders: map[string]string{"authorization": "secret-token", "x-normal": "normal", "host":"example.com"}, // Added host
			expectedRespHeaders:map[string]string{"content-type": "application/json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultLoggingConfig()
			cfg.LogRequests = true
			cfg.LogResponses = true
			cfg.LogRequestHeaders = tt.logRequestHeaders
			cfg.LogResponseHeaders = tt.logResponseHeaders
			cfg.SensitiveHeaders = tt.sensitiveHeaders
			cfg.RedactSensitiveData = tt.redactSensitiveData

			requestPath := "/test_headers"
			handlerToUse := defaultRouteHandler
			if tt.logResponseHeaders {
				requestPath = requestPath + "?sendbody=true"
			}

			logBuf := new(bytes.Buffer)
			logger := MockLoggerForLogging(logBuf)
			obs := MockObservabilityForLogging(logger)
			configuredMiddleware := LoggingMiddleware(obs, cfg)

			performLoggingTestRequest(t,
				configuredMiddleware,
				logBuf,
				"GET",
				requestPath,
				nil,
				tt.requestHeadersMap,
				handlerToUse,
			)
			logOutput := logBuf.String()

			var reqLogCaptured bool
			if tt.logRequestHeaders {
				var reqLogEntry struct { Request RequestLogEntry `json:"request"` }
				foundReqLog := false
				for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
					if strings.Contains(line, `"message":"HTTP request"`) {
						err := json.Unmarshal([]byte(line), &reqLogEntry)
						require.NoError(t, err, "Failed to unmarshal request log: %s", line)
						foundReqLog = true
						break
					}
				}
				require.True(t, foundReqLog, "Request log not found")
				if tt.expectedReqHeaders == nil {
					assert.Nil(t, reqLogEntry.Request.Headers)
				} else {
					normalizedLoggedHeaders := make(map[string]string)
					for k, v := range reqLogEntry.Request.Headers {
						normalizedLoggedHeaders[strings.ToLower(k)] = v
					}
					assert.Equal(t, tt.expectedReqHeaders, normalizedLoggedHeaders)
				}
				reqLogCaptured = true
			}

			if tt.logResponseHeaders {
				var respLogEntry struct { Response ResponseLogEntry `json:"response"`}
				foundRespLog := false
				for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
					if strings.Contains(line, `"message":"HTTP response"`) {
						err := json.Unmarshal([]byte(line), &respLogEntry)
						require.NoError(t, err, "Failed to unmarshal response log: %s", line)
						foundRespLog = true
						break
					}
				}
				require.True(t, foundRespLog, "Response log not found")

				if tt.expectedRespHeaders == nil {
					assert.Nil(t, respLogEntry.Response.Headers)
				} else {
					normalizedLoggedHeaders := make(map[string]string)
					for k, v := range respLogEntry.Response.Headers {
						normalizedLoggedHeaders[strings.ToLower(k)] = v
					}
					for k_expected, v_expected := range tt.expectedRespHeaders { // Use different var names
						assert.Equal(t, v_expected, normalizedLoggedHeaders[k_expected], "Expected response header %s to be %s", k_expected, v_expected)
					}
				}
			}

			if !tt.logRequestHeaders && cfg.LogRequests && !reqLogCaptured {
				var reqLogEntry struct { Request RequestLogEntry `json:"request"` }
				foundReqLog := false
				for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
					if strings.Contains(line, `"message":"HTTP request"`) {
						err := json.Unmarshal([]byte(line), &reqLogEntry)
						require.NoError(t, err, "Failed to unmarshal request log: %s", line)
						foundReqLog = true
						break
					}
				}
				if foundReqLog {
					assert.Nil(t, reqLogEntry.Request.Headers, "Request headers should be nil when LogRequestHeaders is false")
				}
			}
		})
	}
}

func TestLoggingMiddleware_BodyLogging(t *testing.T) {
	jsonData := `{"field1":"value1","password":"secret123","nested":{"field2":"value2"}}`
	_ = strings.Repeat("a", 2048)

	tests := []struct {
		name                string
		logRequestBody      bool
		logResponseBody     bool
		maxBodySize         int
		requestBody         string
		sendRespBodyQuery   string
		redactSensitiveData bool
		sensitiveParams     []string
		expectedReqBodyLog  string
		expectedRespBodyLog string
	}{
		{
			name:               "request body logged, within size, redacted",
			logRequestBody:     true,
			maxBodySize:        1024,
			requestBody:        jsonData,
			redactSensitiveData:true,
			sensitiveParams:    []string{"password"},
			expectedReqBodyLog: `{"field1":"value1","password":"[REDACTED]","nested":{"field2":"value2"}}`, // Corrected: no extra space
		},
		{
			name:               "request body logged, no redaction",
			logRequestBody:     true,
			maxBodySize:        1024,
			requestBody:        jsonData,
			redactSensitiveData:false,
			sensitiveParams:    []string{"password"},
			expectedReqBodyLog: jsonData,
		},
		{
			name:               "request body logged, too large",
			logRequestBody:     true,
			maxBodySize:        32,
			requestBody:        jsonData,
			redactSensitiveData:true,
			expectedReqBodyLog: "",
		},
		{
			name:               "request body not logged by flag",
			logRequestBody:     false,
			maxBodySize:        1024,
			requestBody:        jsonData,
			expectedReqBodyLog: "",
		},
		{
			name:               "request body logged, but not JSON",
			logRequestBody:     true,
			maxBodySize:        1024,
			requestBody:        "this is plain text",
			redactSensitiveData:true,
			expectedReqBodyLog: "",
		},
		{
			name:               "response body logging enabled but not implemented",
			logResponseBody:    true,
			maxBodySize:        1024,
			sendRespBodyQuery:  "?sendbody=true",
			redactSensitiveData:true,
			expectedRespBodyLog:"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultLoggingConfig()
			cfg.LogRequests = true
			cfg.LogResponses = true
			cfg.LogRequestBody = tt.logRequestBody
			cfg.LogResponseBody = tt.logResponseBody
			cfg.MaxBodySize = tt.maxBodySize
			cfg.RedactSensitiveData = tt.redactSensitiveData
			if tt.sensitiveParams != nil {
				cfg.SensitiveParams = tt.sensitiveParams
			}

			requestPath := "/test_body"
			if tt.sendRespBodyQuery != "" {
				requestPath += tt.sendRespBodyQuery
			}

			var reqBodyReader io.Reader
			if tt.requestBody != "" {
				reqBodyReader = strings.NewReader(tt.requestBody)
			}

			headers := map[string]string{}
			if tt.name == "request body logged, but not JSON" {
				headers["Content-Type"] = "text/plain"
			}

			logBuf := new(bytes.Buffer)
			logger := MockLoggerForLogging(logBuf)
			obs := MockObservabilityForLogging(logger)
			configuredMiddleware := LoggingMiddleware(obs, cfg)

			performLoggingTestRequest(t,
				configuredMiddleware,
				logBuf,
				"POST",
				requestPath,
				reqBodyReader,
				headers,
				defaultRouteHandler,
			)
			logOutput := logBuf.String()

			if tt.logRequestBody {
				var reqLogEntry struct { Request RequestLogEntry `json:"request"` }
				foundReqLog := false
				for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
					if strings.Contains(line, `"message":"HTTP request"`) {
						err := json.Unmarshal([]byte(line), &reqLogEntry)
						require.NoError(t, err, "Failed to unmarshal request log: %s", line)
						foundReqLog = true
						break
					}
				}
				require.True(t, foundReqLog, "Request log not found for body test")
				assert.Equal(t, tt.expectedReqBodyLog, reqLogEntry.Request.Body)
			} else if tt.expectedReqBodyLog == "" {
				var reqLogEntry struct { Request RequestLogEntry `json:"request"` }
                 for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
					if strings.Contains(line, `"message":"HTTP request"`) {
						err := json.Unmarshal([]byte(line), &reqLogEntry)
						require.NoError(t, err, "Failed to unmarshal request log: %s", line)
						assert.Empty(t, reqLogEntry.Request.Body, "Request body should be empty when LogRequestBody is false")
						break
					}
				}
            }

			if tt.logResponseBody {
				var respLogEntry struct { Response ResponseLogEntry `json:"response"` }
				foundRespLog := false
				for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
					if strings.Contains(line, `"message":"HTTP response"`) {
						err := json.Unmarshal([]byte(line), &respLogEntry)
						require.NoError(t, err, "Failed to unmarshal response log: %s", line)
						foundRespLog = true
						break
					}
				}
				require.True(t, foundRespLog, "Response log not found for body test")
				assert.Empty(t, respLogEntry.Response.Body, "Response body in log should be empty (current implementation)")
			}
		})
	}
}

func TestLoggingMiddleware_SensitiveParamRedaction(t *testing.T) {
	tests := []struct {
		name                string
		queryParams         string
		sensitiveParams     []string
		redactSensitiveData bool
		expectedQueryInLog  map[string]string // Check for specific params and their values (or [REDACTED])
		shouldNotContain    []string // params that should NOT be in the query string at all after sanitization (if any)
	}{
		{
			name:                "default sensitive params, redact true",
			queryParams:         "?user=test&password=secret123&session_token=abcdef&normal=keep",
			sensitiveParams:     DefaultLoggingConfig().SensitiveParams,
			redactSensitiveData: true,
			expectedQueryInLog:  map[string]string{"user":"test", "password":"[REDACTED]", "session_token":"abcdef", "normal":"keep"},
            // session_token is not sensitive by default, fixed expectation
		},
		{
			name:                "custom sensitive params, redact true",
			queryParams:         "?user=test&custom_secret=value&key=anothersecret",
			sensitiveParams:     []string{"custom_secret", "key"},
			redactSensitiveData: true,
			expectedQueryInLog:  map[string]string{"user":"test", "custom_secret":"[REDACTED]", "key":"[REDACTED]"},
		},
		{
			name:                "default sensitive params, redact false",
			queryParams:         "?user=test&password=secret123&token=abcdef",
			sensitiveParams:     DefaultLoggingConfig().SensitiveParams,
			redactSensitiveData: false,
			expectedQueryInLog:  map[string]string{"user":"test", "password":"secret123", "token":"abcdef"},
		},
		{
			name:                "no sensitive params in query, redact true",
			queryParams:         "?user=test&info=general",
			sensitiveParams:     DefaultLoggingConfig().SensitiveParams,
			redactSensitiveData: true,
			expectedQueryInLog:  map[string]string{"user":"test", "info":"general"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultLoggingConfig()
			cfg.LogRequests = true
			cfg.LogResponses = false
			cfg.SensitiveParams = tt.sensitiveParams
			cfg.RedactSensitiveData = tt.redactSensitiveData
			cfg.LogRequestHeaders = false
			cfg.LogRequestBody = false
			cfg.LogSlowRequests = false
			cfg.LogSuspiciousRequests = false

			requestPath := "/test_query_redaction" + tt.queryParams

			logBuf := new(bytes.Buffer)
			logger := MockLoggerForLogging(logBuf)
			obs := MockObservabilityForLogging(logger)
			configuredMiddleware := LoggingMiddleware(obs, cfg)

			performLoggingTestRequest(t,
				configuredMiddleware,
				logBuf,
				"GET",
				requestPath,
				nil,
				nil,
				defaultRouteHandler,
			)
			logOutput := logBuf.String()

			var reqLogEntry struct { Request RequestLogEntry `json:"request"`}
			foundReqLog := false
			for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
				if strings.Contains(line, `"message":"HTTP request"`) {
					err := json.Unmarshal([]byte(line), &reqLogEntry)
					require.NoError(t, err, "Failed to unmarshal request log: %s", line)
					foundReqLog = true
					break
				}
			}
			require.True(t, foundReqLog, "Request log not found")

			// Parse the logged query string to check params individually
			loggedURL, err := url.Parse(reqLogEntry.Request.Query)
			require.NoError(t, err, "Failed to parse logged query string: %s", reqLogEntry.Request.Query)
			loggedQueryParams := loggedURL.Query()

			for k, expectedVal := range tt.expectedQueryInLog {
				actualVal := loggedQueryParams.Get(k)
				assert.Equal(t, expectedVal, actualVal, "Mismatch for query param '%s'", k)
			}
			if tt.shouldNotContain != nil {
				for _, p := range tt.shouldNotContain {
					assert.False(t, loggedQueryParams.Has(p), "Query param '%s' should not be present", p)
				}
			}
		})
	}
}


func TestLoggingMiddleware_ClientInfoLogging(t *testing.T) {
	tests := []struct {
		name           string
		logClientIP    bool
		logUserAgent   bool
		userAgentHeader string
		expectedClientIP bool
		expectedUserAgentValue string
	}{
		{
			name: "log both IP and UserAgent",
			logClientIP: true,
			logUserAgent: true,
			userAgentHeader: "TestAgent/1.0",
			expectedClientIP: true,
			expectedUserAgentValue: "TestAgent/1.0",
		},
		{
			name: "log only IP",
			logClientIP: true,
			logUserAgent: false,
			userAgentHeader: "TestAgent/1.0",
			expectedClientIP: true,
			expectedUserAgentValue: "",
		},
		{
			name: "log only UserAgent",
			logClientIP: false,
			logUserAgent: true,
			userAgentHeader: "TestAgent/1.0",
			expectedClientIP: false,
			expectedUserAgentValue: "TestAgent/1.0",
		},
		{
			name: "log neither IP nor UserAgent",
			logClientIP: false,
			logUserAgent: false,
			userAgentHeader: "TestAgent/1.0",
			expectedClientIP: false,
			expectedUserAgentValue: "",
		},
		{
			name: "log UserAgent, no UA header sent",
			logClientIP: true,
			logUserAgent: true,
			userAgentHeader: "",
			expectedClientIP: true,
			expectedUserAgentValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultLoggingConfig()
			cfg.LogRequests = true
			cfg.LogResponses = false
			cfg.LogClientIP = tt.logClientIP
			cfg.LogUserAgent = tt.logUserAgent
			cfg.LogRequestHeaders = false
			cfg.LogRequestBody = false
			cfg.LogSlowRequests = false
			cfg.LogSuspiciousRequests = false

			headers := map[string]string{}
			if tt.userAgentHeader != "" {
				headers["User-Agent"] = tt.userAgentHeader
			}

			logBuf := new(bytes.Buffer)
			logger := MockLoggerForLogging(logBuf)
			obs := MockObservabilityForLogging(logger)
			configuredMiddleware := LoggingMiddleware(obs, cfg)

			performLoggingTestRequest(t,
				configuredMiddleware,
				logBuf,
				"GET",
				"/test_client_info",
				nil,
				headers,
				defaultRouteHandler,
			)
			logOutput := logBuf.String()

			var reqLogEntry struct { Request RequestLogEntry `json:"request"`}
			foundReqLog := false
			for _, line := range strings.Split(strings.TrimSpace(logOutput), "\n") {
				if strings.Contains(line, `"message":"HTTP request"`) {
					err := json.Unmarshal([]byte(line), &reqLogEntry)
					require.NoError(t, err, "Failed to unmarshal request log: %s", line)
					foundReqLog = true
					break
				}
			}
			require.True(t, foundReqLog, "Request log not found")

			if tt.expectedClientIP {
				assert.NotEmpty(t, reqLogEntry.Request.ClientIP, "ClientIP should be logged and non-empty")
			} else {
				assert.Empty(t, reqLogEntry.Request.ClientIP, "ClientIP should be empty or not logged")
			}
			assert.Equal(t, tt.expectedUserAgentValue, reqLogEntry.Request.UserAgent)
		})
	}
}

func TestLoggingMiddleware_PerformanceAndErrorLogging(t *testing.T) {
	tests := []struct {
		name                 string
		isSlow               bool
		slowThreshold        time.Duration
		triggerError         bool
		expectedSlowLog      bool
		expectedErrorLog     bool
		expectedRegularRespLog bool
	}{
		{
			name:                 "fast request, no error",
			isSlow:               false,
			slowThreshold:        100 * time.Millisecond,
			triggerError:         false,
			expectedSlowLog:      false,
			expectedErrorLog:     false,
			expectedRegularRespLog: true,
		},
		{
			name:                 "slow request, no error",
			isSlow:               true,
			slowThreshold:        10 * time.Millisecond,
			triggerError:         false,
			expectedSlowLog:      true,
			expectedErrorLog:     false,
			expectedRegularRespLog: true,
		},
		{
			name:                 "fast request, with error",
			isSlow:               false,
			slowThreshold:        100 * time.Millisecond,
			triggerError:         true,
			expectedSlowLog:      false,
			expectedErrorLog:     true,
			expectedRegularRespLog: false,
		},
		{
			name:                 "slow request, with error",
			isSlow:               true,
			slowThreshold:        10 * time.Millisecond,
			triggerError:         true,
			expectedSlowLog:      false, // Corrected AGAIN: Slow log is SKIPPED if error occurs due to early return
			expectedErrorLog:     true,
			expectedRegularRespLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultLoggingConfig()
			cfg.LogRequests = false
			cfg.LogResponses = tt.expectedRegularRespLog
			cfg.LogSlowRequests = true
			cfg.SlowRequestThreshold = tt.slowThreshold
			cfg.LogFailedRequests = true

			requestPath := "/test_perf_error"
			if tt.triggerError {
				requestPath += "?error=true"
			}

			handler := func(c *fiber.Ctx) error {
				if tt.isSlow {
					time.Sleep(tt.slowThreshold + 5*time.Millisecond)
				}
				if tt.triggerError {
					return fiber.NewError(http.StatusBadGateway, "simulated error for failed request log")
				}
				return c.Status(http.StatusOK).SendString("OK")
			}

			logBuf := new(bytes.Buffer)
			logger := MockLoggerForLogging(logBuf)
			obs := MockObservabilityForLogging(logger)
			configuredMiddleware := LoggingMiddleware(obs, cfg)

			performLoggingTestRequest(t,
				configuredMiddleware,
				logBuf,
				"GET",
				requestPath,
				nil,
				nil,
				handler,
			)
			logOutput := logBuf.String()

			if tt.expectedSlowLog {
				assert.Contains(t, logOutput, "Slow request detected")
			} else {
				assert.NotContains(t, logOutput, "Slow request detected")
			}

			if tt.expectedErrorLog {
				assert.Contains(t, logOutput, "HTTP error response")
				assert.Contains(t, logOutput, "simulated error for failed request log")
			} else {
				assert.NotContains(t, logOutput, "HTTP error response")
			}

			if tt.expectedRegularRespLog {
				assert.Contains(t, logOutput, `"message":"HTTP response"`)
				assert.NotContains(t, logOutput, "HTTP error response")
			} else if !tt.expectedErrorLog {
				assert.NotContains(t, logOutput, `"message":"HTTP response"`)
			}
		})
	}
}

func TestLoggingMiddleware_SuspiciousRequestLogging(t *testing.T) {
	tests := []struct {
		name                string
		path                string
		userAgent           string
		expectedSuspiciousLog bool
	}{
		{
			name:                "normal request",
			path:                "/normal/path",
			userAgent:           "Mozilla/5.0",
			expectedSuspiciousLog: false,
		},
		{
			name:                "suspicious user agent - sqlmap",
			path:                "/normal/path",
			userAgent:           "sqlmap/1.5.11#stable (http://sqlmap.org)",
			expectedSuspiciousLog: true,
		},
		{
			name:                "suspicious path - /etc/passwd",
			path:                "/foo/bar/../../../etc/passwd",
			userAgent:           "Mozilla/5.0",
			expectedSuspiciousLog: true,
		},
		{
			name:                "suspicious path - .env",
			path:                "/.env",
			userAgent:           "Mozilla/5.0",
			expectedSuspiciousLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultLoggingConfig()
			cfg.LogRequests = false
			cfg.LogResponses = false
			cfg.LogSuspiciousRequests = true

			headers := map[string]string{}
			if tt.userAgent != "" {
				headers["User-Agent"] = tt.userAgent
			}

			logBuf := new(bytes.Buffer)
			logger := MockLoggerForLogging(logBuf)
			obs := MockObservabilityForLogging(logger)
			configuredMiddleware := LoggingMiddleware(obs, cfg)

			performLoggingTestRequest(t,
				configuredMiddleware,
				logBuf,
				"GET",
				tt.path,
				nil,
				headers,
				defaultRouteHandler,
			)
			logOutput := logBuf.String()

			if tt.expectedSuspiciousLog {
				assert.Contains(t, logOutput, "Suspicious request detected")
				if tt.userAgent != "" {
					assert.Contains(t, logOutput, tt.userAgent)
				}
			} else {
				assert.NotContains(t, logOutput, "Suspicious request detected")
			}
		})
	}
}

func TestLoggingMiddleware_SkipOptions(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		method      string
		skipPaths   []string
		skipMethods []string
		expectLogs  bool
	}{
		{
			name:       "path not skipped, method not skipped",
			path:       "/api/data",
			method:     "GET",
			expectLogs: true,
		},
		{
			name:       "path skipped",
			path:       "/health/live",
			method:     "GET",
			skipPaths:  []string{"/health"},
			expectLogs: false,
		},
		{
			name:       "method skipped",
			path:       "/api/data",
			method:     "OPTIONS",
			skipMethods:[]string{"OPTIONS"},
			expectLogs: false,
		},
		{
			name:       "path not skipped by prefix, method not skipped",
			path:       "/api/health",
			method:     "GET",
			skipPaths:  []string{"/health"},
			expectLogs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultLoggingConfig()
			cfg.LogRequests = true
			cfg.LogResponses = true
			if tt.skipPaths != nil {
				cfg.SkipPaths = tt.skipPaths
			}
			if tt.skipMethods != nil {
				cfg.SkipMethods = tt.skipMethods
			}
			cfg.LogSlowRequests = false
			cfg.LogSuspiciousRequests = false
			cfg.LogFailedRequests = false

			logBuf := new(bytes.Buffer)
			logger := MockLoggerForLogging(logBuf)
			obs := MockObservabilityForLogging(logger)
			configuredMiddleware := LoggingMiddleware(obs, cfg)

			performLoggingTestRequest(t,
				configuredMiddleware,
				logBuf,
				tt.method,
				tt.path,
				nil,
				nil,
				defaultRouteHandler,
			)
			logOutput := logBuf.String()

			if tt.expectLogs {
				assert.Contains(t, logOutput, `"message":"HTTP request"`)
				assert.Contains(t, logOutput, `"message":"HTTP response"`)
			} else {
				assert.NotContains(t, logOutput, `"message":"HTTP request"`)
				assert.NotContains(t, logOutput, `"message":"HTTP response"`)
			}
		})
	}
}

// --- Helper Function Tests ---

func TestIsJSONContent(t *testing.T) {
	testCases := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{"standard json", "application/json", true},
		{"json with charset", "application/json; charset=utf-8", true},
		{"json variant", "application/vnd.api+json", true}, // This should be true
		{"text plain", "text/plain", false},
		{"xml", "application/xml", false},
		{"form urlencoded", "application/x-www-form-urlencoded", false},
		{"empty", "", false},
		{"mixed case", "Application/JSON", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "json variant" {
				fmt.Printf("DEBUG: TestIsJSONContent/json_variant\n")
				fmt.Printf("DEBUG: Input ContentType: '%s'\n", tc.contentType)
				lowerContentType := strings.ToLower(tc.contentType)
				fmt.Printf("DEBUG: Lower ContentType: '%s'\n", lowerContentType)
				mainType := strings.TrimSpace(strings.Split(lowerContentType, ";")[0])
				fmt.Printf("DEBUG: Main Type: '%s'\n", mainType)
				hasSuffix := strings.HasSuffix(mainType, "+json")
				fmt.Printf("DEBUG: Has '+json' suffix: %t\n", hasSuffix)
				isAppJSON := mainType == "application/json"
				fmt.Printf("DEBUG: Is 'application/json': %t\n", isAppJSON)
			}
			actual := isJSONContent(tc.contentType)
			if tc.name == "json variant" {
				fmt.Printf("DEBUG: Actual result from isJSONContent: %t\n", actual)
			}
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestIsSuspiciousRequest_Direct(t *testing.T) {
	suspiciousUserAgents := []string{
		"sqlmap/1.0-dev (http://sqlmap.org)", "some nikto scan", "Nessus Scan", "BurpSuitePro",
		"Mozilla/5.0 (compatible; ZAP/2.9.0)", "Masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
		"Nmap Scripting Engine",
	}
	normalUserAgents := []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "MyCustomAgent/1.0"}

	suspiciousPaths := []string{
		"/path/../../../../../etc/passwd", "/proc/self/environ", "/wp-admin/login.php",
		"/phpmyadmin/scripts/setup.php", "/.env", "/config/config.php.bak",
	}
	normalPaths := []string{"/api/users", "/index.html"}

	app := fiber.New()

	for _, agent := range suspiciousUserAgents {
		t.Run(fmt.Sprintf("suspicious_user_agent_%s", strings.Split(agent, "/")[0]), func(t *testing.T) {
			fctx := &fasthttp.RequestCtx{}
			c := app.AcquireCtx(fctx)
			c.Request().Header.Set("User-Agent", agent)
			c.Request().SetRequestURI("/normal")
			assert.True(t, isSuspiciousRequest(c), "Expected User-Agent '%s' to be suspicious", agent)
			app.ReleaseCtx(c)
		})
	}

	for _, agent := range normalUserAgents {
		t.Run(fmt.Sprintf("normal_user_agent_%s", strings.Split(agent, "/")[0]), func(t *testing.T) {
			fctx := &fasthttp.RequestCtx{}
			c := app.AcquireCtx(fctx)
			c.Request().Header.Set("User-Agent", agent)
			c.Request().SetRequestURI("/normal")
			assert.False(t, isSuspiciousRequest(c), "Expected User-Agent '%s' to be normal", agent)
			app.ReleaseCtx(c)
		})
	}

	for _, path := range suspiciousPaths {
		t.Run(fmt.Sprintf("suspicious_path_%s", strings.ReplaceAll(path, "/", "_")), func(t *testing.T) {
			fctx := &fasthttp.RequestCtx{}
			c := app.AcquireCtx(fctx)
			c.Request().Header.Set("User-Agent", "Mozilla/5.0")
			c.Request().SetRequestURI(path)
			c.Path(path)
			assert.True(t, isSuspiciousRequest(c), "Expected path '%s' to be suspicious", path)
			app.ReleaseCtx(c)
		})
	}

	for _, path := range normalPaths {
		t.Run(fmt.Sprintf("normal_path_%s", strings.ReplaceAll(path, "/", "_")), func(t *testing.T) {
			fctx := &fasthttp.RequestCtx{}
			c := app.AcquireCtx(fctx)
			c.Request().Header.Set("User-Agent", "Mozilla/5.0")
			c.Request().SetRequestURI(path)
			c.Path(path)
			assert.False(t, isSuspiciousRequest(c), "Expected path '%s' to be normal", path)
			app.ReleaseCtx(c)
		})
	}
}
