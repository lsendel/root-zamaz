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

type Config struct {
    URL         string `env:"NATS_URL" envDefault:"nats://localhost:4222"`
    ClusterName string `env:"NATS_CLUSTER" envDefault:"mvp-cluster"`
    ClientID    string `env:"NATS_CLIENT_ID"`
}

type Client struct {
    conn   *nats.Conn
    js     nats.JetStreamContext
    tracer trace.Tracer
}

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
