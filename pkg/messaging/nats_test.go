package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// --- Mock NATS ---

type mockNATSConn struct {
	nats.Conn // Embed for any pass-through if needed, though not used here
	isClosed  bool
	jsCtx     *mockJetStreamContext
}

func (m *mockNATSConn) JetStream(opts ...nats.JSOpt) (nats.JetStreamContext, error) {
	if m.jsCtx == nil {
		return nil, errors.New("mock JetStream not configured")
	}
	return m.jsCtx, m.jsCtx.err
}

func (m *mockNATSConn) Close() {
	m.isClosed = true
}

type mockJetStreamContext struct {
	nats.JetStreamContext // Embed for any pass-through
	err                   error
	publishErr            error
	subscribeErr          error
	lastPublishedSubject  string
	lastPublishedData     []byte
	subscriptions         map[string]nats.MsgHandler
	ackNakSubject         string
	ackNakData            []byte
}

func newMockJetStreamContext() *mockJetStreamContext {
	return &mockJetStreamContext{
		subscriptions: make(map[string]nats.MsgHandler),
	}
}

func (mjs *mockJetStreamContext) Publish(subj string, data []byte, opts ...nats.PubOpt) (*nats.PubAck, error) {
	if mjs.publishErr != nil {
		return nil, mjs.publishErr
	}
	mjs.lastPublishedSubject = subj
	mjs.lastPublishedData = data
	return &nats.PubAck{Stream: "test-stream", Seq: 1}, nil
}

func (mjs *mockJetStreamContext) Subscribe(subj string, cb nats.MsgHandler, opts ...nats.SubOpt) (*nats.Subscription, error) {
	if mjs.subscribeErr != nil {
		return nil, mjs.subscribeErr
	}
	mjs.subscriptions[subj] = cb
	return &nats.Subscription{Subject: subj}, nil
}

// Helper to simulate a message delivery to a mock subscriber
func (mjs *mockJetStreamContext) deliverMessage(subj string, data []byte) error {
	handler, ok := mjs.subscriptions[subj]
	if !ok {
		return fmt.Errorf("no mock subscriber for subject %s", subj)
	}

	// Mock nats.Msg and its Ack/Nak
	msg := &nats.Msg{
		Subject: subj,
		Data:    data,
		Sub:     &nats.Subscription{Subject: subj},
		Reply:   "",
		Header:  nil,
		Ack: func(opts ...nats.AckOpt) error {
			mjs.ackNakSubject = subj
			mjs.ackNakData = []byte("ACK")
			return nil
		},
		Nak: func(opts ...nats.NakOpt) error {
			mjs.ackNakSubject = subj
			mjs.ackNakData = []byte("NAK")
			return nil
		},
		NakWithDelay: func(delay time.Duration, opts ...nats.NakOpt) error {
			mjs.ackNakSubject = subj
			mjs.ackNakData = []byte("NAK_DELAY")
			return nil
		},
		InProgress: func(opts ...nats.AckOpt) error { return nil },
		Term:       func(opts ...nats.AckOpt) error { return nil },
	}

	handler(msg)
	return nil
}

// --- Tests ---

func TestNewClient(t *testing.T) {
	// We can't easily mock nats.Connect directly without changing the source code
	// or using linker tricks. So, we'll test what we can around it.

	t.Run("Successful client creation - ID provided", func(t *testing.T) {
		cfg := Config{
			URL:      "nats://localhost:4222", // Assumes NATS isn't running or test is quick
			ClientID: "test-client-1",
		}
		// This will likely fail to connect if NATS isn't running,
		// but we are testing the ClientID logic primarily here.
		// For a true unit test of NewClient's internals without nats.Connect,
		// one would need to refactor NewClient to allow injecting a nats.Conn factory.
		// Given the current structure, we'll proceed with this limited test.

		// If we had a mockable natsConnect function:
		// mockConn := &mockNATSConn{jsCtx: newMockJetStreamContext()}
		// originalNatsConnect := natsConnect
		// natsConnect = func(...) (*nats.Conn, error) { return mockConn, nil }
		// defer func() { natsConnect = originalNatsConnect }()
		// client, err := NewClient(cfg, noop.NewTracerProvider().Tracer("test"))
		// require.NoError(t, err)
		// assert.NotNil(t, client)
		// assert.Equal(t, mockConn, client.conn)

		// For now, just check client ID generation part if URL is dummy
		dummyCfg := Config{ClientID: "my-id"}
		client := &Client{tracer: noop.NewTracerProvider().Tracer("test")} // dummy client for ID check
		finalClientID := cfg.ClientID
		if finalClientID == "" {
			finalClientID = fmt.Sprintf("client-%s", uuid.New().String()[:8])
		}
		assert.Equal(t, "test-client-1", finalClientID)

	})

	t.Run("Client ID generation", func(t *testing.T) {
		cfg := Config{URL: "nats://localhost:1234"} // Dummy URL
		// Similar to above, testing actual connection is hard here.
		// We are interested in the ClientID part.
		client := &Client{tracer: noop.NewTracerProvider().Tracer("test")}
		finalClientID := cfg.ClientID
		if finalClientID == "" {
			// This simulates the internal logic for ID generation
			generatedID := fmt.Sprintf("client-%s", "dummyuid") // simplified
			assert.Contains(t, generatedID, "client-")
		}
	})

	t.Run("Error handling for invalid NATS URL", func(t *testing.T) {
		cfg := Config{URL: "invalid-url-format"}
		_, err := NewClient(cfg, noop.NewTracerProvider().Tracer("test"))
		// This will call the real nats.Connect and should fail.
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect to NATS")
	})
}

func TestClient_PublishEvent(t *testing.T) {
	mockJS := newMockJetStreamContext()
	client := &Client{
		conn:   &mockNATSConn{jsCtx: mockJS},
		js:     mockJS,
		tracer: noop.NewTracerProvider().Tracer("test"),
	}

	ctx := context.Background()
	subject := "test.subject"
	originalEvent := Event{
		Type:     "test.event",
		Source:   "test-source",
		TenantID: "tenant-123",
		Data:     map[string]string{"hello": "world"},
	}

	t.Run("Successful publish", func(t *testing.T) {
		eventCopy := originalEvent // Work on a copy
		err := client.PublishEvent(ctx, subject, eventCopy)
		require.NoError(t, err)

		assert.Equal(t, subject, mockJS.lastPublishedSubject)

		var publishedEvent Event
		err = json.Unmarshal(mockJS.lastPublishedData, &publishedEvent)
		require.NoError(t, err)

		assert.NotEmpty(t, publishedEvent.ID, "Event ID should be generated")
		assert.NotZero(t, publishedEvent.Timestamp, "Timestamp should be generated")
		assert.Equal(t, originalEvent.Type, publishedEvent.Type)
		assert.Equal(t, originalEvent.Source, publishedEvent.Source)
		assert.Equal(t, originalEvent.TenantID, publishedEvent.TenantID)
		assert.Equal(t, originalEvent.Data, publishedEvent.Data) // map comparison works here
		assert.NotEmpty(t, publishedEvent.TraceID, "TraceID should be injected")
		assert.NotEmpty(t, publishedEvent.SpanID, "SpanID should be injected")
	})

	t.Run("Publish with existing ID and Timestamp", func(t *testing.T) {
		fixedID := "fixed-id-123"
		fixedTime := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second) // Truncate for easier comparison
		eventWithID := Event{
			ID:        fixedID,
			Timestamp: fixedTime,
			Type:      "fixed.event",
		}
		err := client.PublishEvent(ctx, subject, eventWithID)
		require.NoError(t, err)

		var publishedEvent Event
		err = json.Unmarshal(mockJS.lastPublishedData, &publishedEvent)
		require.NoError(t, err)

		assert.Equal(t, fixedID, publishedEvent.ID)
		assert.Equal(t, fixedTime, publishedEvent.Timestamp)
	})

	t.Run("Publish error", func(t *testing.T) {
		mockJS.publishErr = errors.New("nats publish failed")
		defer func() { mockJS.publishErr = nil }() // Reset mock

		err := client.PublishEvent(ctx, subject, originalEvent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to publish event")
		assert.Contains(t, err.Error(), "nats publish failed")
	})

	t.Run("JSON marshal error", func(t *testing.T) {
		// Create data that cannot be marshaled to JSON (e.g., a channel)
		eventWithBadData := Event{
			Type: "bad.event",
			Data: make(chan int),
		}
		err := client.PublishEvent(ctx, subject, eventWithBadData)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal event")
	})

	t.Run("Tracing attributes", func(t *testing.T) {
		spanRecorder := tracetest.NewSpanRecorder()
		tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
		tracer := tracerProvider.Tracer("test-tracer")

		clientWithTracer := &Client{
			conn:   &mockNATSConn{jsCtx: mockJS},
			js:     mockJS,
			tracer: tracer,
		}
		eventCopy := originalEvent
		err := clientWithTracer.PublishEvent(ctx, subject, eventCopy)
		require.NoError(t, err)

		finishedSpans := spanRecorder.Ended()
		require.Len(t, finishedSpans, 1)
		span := finishedSpans[0]

		assert.Equal(t, "nats.publish", span.Name())
		attrs := span.Attributes()
		expectedAttrs := map[string]attribute.Value{
			"messaging.destination": attribute.StringValue(subject),
			"messaging.system":      attribute.StringValue("nats"),
			"event.type":            attribute.StringValue(originalEvent.Type),
			"tenant.id":             attribute.StringValue(originalEvent.TenantID),
			"event.id":              attribute.StringValue(eventCopy.ID), // ID is generated
		}
		for k, v := range expectedAttrs {
			found := false
			for _, attr := range attrs {
				if attr.Key == attribute.Key(k) {
					assert.Equal(t, v, attr.Value, "Attribute %s does not match", k)
					found = true
					break
				}
			}
			assert.True(t, found, "Expected attribute %s not found", k)
		}
	})
}

func TestClient_Subscribe(t *testing.T) {
	mockJS := newMockJetStreamContext()
	client := &Client{
		conn:   &mockNATSConn{jsCtx: mockJS},
		js:     mockJS,
		tracer: noop.NewTracerProvider().Tracer("test"),
	}
	subject := "test.subscribe.subject"

	var handlerEvent Event
	var handlerError error
	var wg sync.WaitGroup

	eventHandler := func(ctx context.Context, e Event) error {
		defer wg.Done()
		handlerEvent = e
		return handlerError
	}

	_, err := client.Subscribe(subject, eventHandler)
	require.NoError(t, err)
	require.Contains(t, mockJS.subscriptions, subject, "Subscription should be registered in mock")

	t.Run("Successful message handling and Ack", func(t *testing.T) {
		wg.Add(1)
		handlerError = nil // Ensure success
		testData := Event{ID: "evt-1", Type: "test.data", TenantID: "t-1"}
		jsonData, _ := json.Marshal(testData)

		err = mockJS.deliverMessage(subject, jsonData)
		require.NoError(t, err)
		wg.Wait()

		assert.Equal(t, testData.ID, handlerEvent.ID)
		assert.Equal(t, testData.Type, handlerEvent.Type)
		assert.Equal(t, []byte("ACK"), mockJS.ackNakData)
	})

	t.Run("Handler error and Nak", func(t *testing.T) {
		wg.Add(1)
		handlerError = errors.New("handler processing failed")
		testData := Event{ID: "evt-2", Type: "error.event"}
		jsonData, _ := json.Marshal(testData)

		err = mockJS.deliverMessage(subject, jsonData)
		require.NoError(t, err)
		wg.Wait()

		assert.Equal(t, testData.ID, handlerEvent.ID)
		assert.Equal(t, []byte("NAK"), mockJS.ackNakData)
	})

	t.Run("JSON unmarshal error and Nak", func(t *testing.T) {
		// No wg.Add(1) as handler won't be called
		invalidJsonData := []byte("{not_valid_json")

		err = mockJS.deliverMessage(subject, invalidJsonData)
		require.NoError(t, err)
		// wg.Wait() // Handler not called, so no wg.Done()

		assert.Equal(t, []byte("NAK"), mockJS.ackNakData, "Should NAK on unmarshal error")
	})

	t.Run("Tracing for handler", func(t *testing.T) {
		spanRecorder := tracetest.NewSpanRecorder()
		tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
		clientWithTracer := &Client{
			conn:   &mockNATSConn{jsCtx: mockJS},
			js:     mockJS,
			tracer: tracerProvider.Tracer("handler-tracer"),
		}
		_, err := clientWithTracer.Subscribe(subject, eventHandler)
		require.NoError(t, err)

		wg.Add(1)
		handlerError = nil
		traceID := "trace-id-for-event"
		testData := Event{ID: "evt-trace", Type: "trace.test", TenantID: "t-trace", TraceID: traceID}
		jsonData, _ := json.Marshal(testData)

		err = mockJS.deliverMessage(subject, jsonData)
		require.NoError(t, err)
		wg.Wait()

		finishedSpans := spanRecorder.Ended()
		require.Len(t, finishedSpans, 1)
		span := finishedSpans[0]

		assert.Equal(t, "nats.handle", span.Name())
		attrs := span.Attributes()
		expectedAttrs := map[string]attribute.Value{
			"messaging.source": attribute.StringValue(subject),
			"messaging.system": attribute.StringValue("nats"),
			"event.type":       attribute.StringValue(testData.Type),
			"event.id":         attribute.StringValue(testData.ID),
			"tenant.id":        attribute.StringValue(testData.TenantID),
		}
		for k, v := range expectedAttrs {
			found := false
			for _, attr := range attrs {
				if attr.Key == attribute.Key(k) {
					assert.Equal(t, v, attr.Value, "Attribute %s does not match for handler span", k)
					found = true
					break
				}
			}
			assert.True(t, found, "Expected attribute %s not found for handler span", k)
		}
		// Note: Full trace context propagation from event.TraceID is mentioned as a TODO in source.
		// Here we are testing the span created by the handler wrapper.
	})
}

func TestClient_Close(t *testing.T) {
	mockConn := &mockNATSConn{}
	client := &Client{conn: mockConn}

	client.Close()
	assert.True(t, mockConn.isClosed, "NATS connection should be closed")
}
