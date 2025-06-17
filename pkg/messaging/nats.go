// Package messaging provides distributed messaging capabilities for the MVP Zero Trust Auth system.
// It wraps NATS JetStream to provide reliable, persistent messaging with observability support.
//
// The package offers:
//   - Reliable message publishing with acknowledgments
//   - Stream-based message consumption with at-least-once delivery
//   - Automatic distributed tracing integration
//   - Connection resilience with automatic reconnection
//   - JSON message serialization/deserialization
//
// Example usage:
//
//   cfg := messaging.Config{
//       URL: "nats://localhost:4222",
//       ClusterName: "mvp-cluster",
//       ClientID: "auth-service",
//   }
//   
//   client, err := messaging.NewClient(cfg, tracer)
//   if err != nil {
//       log.Fatal(err)
//   }
//   defer client.Close()
//   
//   // Publish a message
//   msg := UserEvent{UserID: "123", Action: "login"}
//   if err := client.Publish(ctx, "user.events", msg); err != nil {
//       log.Error(err)
//   }
//   
//   // Subscribe to messages
//   if err := client.Subscribe(ctx, "user.events", "auth-processor", handleUserEvent); err != nil {
//       log.Error(err)
//   }
package messaging

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/nats-io/nats.go"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
)

// Config holds configuration for NATS messaging client.
// It supports environment variable overrides for flexible deployment.
type Config struct {
    // URL is the NATS server connection string
    URL         string `env:"NATS_URL" envDefault:"nats://localhost:4222"`
    
    // ClusterName identifies the NATS cluster for JetStream
    ClusterName string `env:"NATS_CLUSTER" envDefault:"mvp-cluster"`
    
    // ClientID uniquely identifies this client instance (auto-generated if empty)
    ClientID    string `env:"NATS_CLIENT_ID"`
}

// Client provides a high-level interface for NATS JetStream messaging.
// It wraps the NATS connection and JetStream context with observability support.
type Client struct {
    // conn is the underlying NATS connection
    conn   *nats.Conn
    
    // js provides JetStream operations for reliable messaging
    js     nats.JetStreamContext
    
    // tracer enables distributed tracing for message operations
    tracer trace.Tracer
}

// NewClient creates and initializes a new NATS messaging client.
// It establishes a connection to the NATS server and sets up JetStream context
// for reliable messaging operations.
//
// The client is configured with automatic reconnection capabilities:
//   - Reconnect wait time: 2 seconds
//   - Max reconnects: unlimited (-1)
//   - Auto-generated client ID if not provided
//
// Parameters:
//   cfg - Configuration for NATS connection
//   tracer - OpenTelemetry tracer for distributed tracing
//
// Returns:
//   A configured Client instance ready for messaging operations
//
// Example:
//   cfg := Config{
//       URL: "nats://localhost:4222",
//       ClusterName: "mvp-cluster",
//   }
//   client, err := NewClient(cfg, tracer)
//   if err != nil {
//       return fmt.Errorf("failed to create messaging client: %w", err)
//   }
//   defer client.Close()
//
// The client automatically generates a unique ClientID if none is provided,
// ensuring each instance can be distinguished in NATS monitoring.
func NewClient(cfg Config, tracer trace.Tracer) (*Client, error) {
    if cfg.ClientID == "" {
        cfg.ClientID = fmt.Sprintf("client-%s", uuid.New().String()[:8])
    }

    nc, err := nats.Connect(cfg.URL,
        nats.Name(cfg.ClientID),
        nats.ReconnectWait(2*time.Second),
        nats.MaxReconnects(-1),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to connect to NATS: %w", err)
    }

    js, err := nc.JetStream()
    if err != nil {
        return nil, fmt.Errorf("failed to create JetStream context: %w", err)
    }

    return &Client{
        conn:   nc,
        js:     js,
        tracer: tracer,
    }, nil
}

type Event struct {
    ID        string                 `json:"id"`
    Type      string                 `json:"type"`
    Source    string                 `json:"source"`
    TenantID  string                 `json:"tenant_id"`
    Data      interface{}            `json:"data"`
    Metadata  map[string]interface{} `json:"metadata"`
    Timestamp time.Time              `json:"timestamp"`
    TraceID   string                 `json:"trace_id"`
    SpanID    string                 `json:"span_id"`
}

func (c *Client) PublishEvent(ctx context.Context, subject string, event Event) error {
    ctx, span := c.tracer.Start(ctx, "nats.publish",
        trace.WithAttributes(
            attribute.String("messaging.destination", subject),
            attribute.String("messaging.system", "nats"),
            attribute.String("event.type", event.Type),
            attribute.String("tenant.id", event.TenantID),
        ),
    )
    defer span.End()

    // Add tracing context to event
    spanCtx := span.SpanContext()
    event.TraceID = spanCtx.TraceID().String()
    event.SpanID = spanCtx.SpanID().String()

    if event.ID == "" {
        event.ID = uuid.New().String()
    }
    if event.Timestamp.IsZero() {
        event.Timestamp = time.Now()
    }
    if event.Metadata == nil {
        event.Metadata = make(map[string]interface{})
    }

    data, err := json.Marshal(event)
    if err != nil {
        span.RecordError(err)
        return fmt.Errorf("failed to marshal event: %w", err)
    }

    _, err = c.js.Publish(subject, data)
    if err != nil {
        span.RecordError(err)
        return fmt.Errorf("failed to publish event: %w", err)
    }

    span.SetAttributes(attribute.String("event.id", event.ID))
    return nil
}

type EventHandler func(context.Context, Event) error

func (c *Client) Subscribe(subject string, handler EventHandler) (*nats.Subscription, error) {
    return c.js.Subscribe(subject, func(msg *nats.Msg) {
        var event Event
        if err := json.Unmarshal(msg.Data, &event); err != nil {
            msg.Nak()
            return
        }

        // Create context with tracing information
        ctx := context.Background()
        if event.TraceID != "" {
            // Note: In a real implementation, you'd reconstruct the trace context
            // from the TraceID and SpanID
        }

        ctx, span := c.tracer.Start(ctx, "nats.handle",
            trace.WithAttributes(
                attribute.String("messaging.source", subject),
                attribute.String("messaging.system", "nats"),
                attribute.String("event.type", event.Type),
                attribute.String("event.id", event.ID),
                attribute.String("tenant.id", event.TenantID),
            ),
        )
        defer span.End()

        if err := handler(ctx, event); err != nil {
            span.RecordError(err)
            msg.Nak()
            return
        }

        msg.Ack()
    })
}

func (c *Client) Close() {
    if c.conn != nil {
        c.conn.Close()
    }
}
