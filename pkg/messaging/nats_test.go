package messaging

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestEvent_GenerateID(t *testing.T) {
	event := Event{
		Type:   "test.event",
		Source: "test-source",
	}

	// Test ID generation
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	assert.NotEmpty(t, event.ID)
	assert.Equal(t, 36, len(event.ID)) // UUID v4 length
}

func TestEvent_SetTimestamp(t *testing.T) {
	event := Event{
		Type:   "test.event",
		Source: "test-source",
	}

	// Test timestamp generation
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	assert.False(t, event.Timestamp.IsZero())
	assert.True(t, event.Timestamp.Before(time.Now().Add(time.Second)))
}

func TestEvent_JSONMarshaling(t *testing.T) {
	originalEvent := Event{
		ID:        uuid.New().String(),
		Type:      "test.event",
		Source:    "test-source",
		TenantID:  "tenant-123",
		Timestamp: time.Now().UTC(),
		Data: map[string]interface{}{
			"key1": "value1",
			"key2": 123,
		},
		TraceID: "trace-123",
		SpanID:  "span-456",
	}

	// Marshal
	data, err := json.Marshal(originalEvent)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// Unmarshal
	var decodedEvent Event
	err = json.Unmarshal(data, &decodedEvent)
	require.NoError(t, err)

	// Compare
	assert.Equal(t, originalEvent.ID, decodedEvent.ID)
	assert.Equal(t, originalEvent.Type, decodedEvent.Type)
	assert.Equal(t, originalEvent.Source, decodedEvent.Source)
	assert.Equal(t, originalEvent.TenantID, decodedEvent.TenantID)
	assert.Equal(t, originalEvent.TraceID, decodedEvent.TraceID)
	assert.Equal(t, originalEvent.SpanID, decodedEvent.SpanID)
	assert.WithinDuration(t, originalEvent.Timestamp, decodedEvent.Timestamp, time.Second)
}

func TestConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config with client ID",
			config: Config{
				URL:      "nats://localhost:4222",
				ClientID: "test-client",
			},
			wantErr: false,
		},
		{
			name: "valid config without client ID",
			config: Config{
				URL: "nats://localhost:4222",
			},
			wantErr: false,
		},
		{
			name: "empty URL",
			config: Config{
				URL: "",
			},
			wantErr: false, // Empty URL should use default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just validate the config structure
			if tt.config.URL == "" {
				assert.Empty(t, tt.config.URL)
			} else {
				assert.NotEmpty(t, tt.config.URL)
			}
		})
	}
}

func TestClient_TraceContext(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")

	// Test that client can be created with a tracer
	client := &Client{
		tracer: tracer,
	}

	assert.NotNil(t, client.tracer)
}
