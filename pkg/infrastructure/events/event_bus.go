// Package events provides event bus implementation for the MVP Zero Trust Auth system.
package events

import (
	"context"
	"fmt"
	"sync"

	"mvp.local/pkg/domain/events"
	"mvp.local/pkg/observability"
)

// EventHandler represents a function that handles domain events
type EventHandler func(ctx context.Context, event events.DomainEvent) error

// EventBus represents an in-memory event bus
type EventBus struct {
	handlers map[string][]EventHandler
	obs      *observability.Observability
	mu       sync.RWMutex
}

// NewEventBus creates a new event bus
func NewEventBus(obs *observability.Observability) *EventBus {
	return &EventBus{
		handlers: make(map[string][]EventHandler),
		obs:      obs,
	}
}

// Subscribe subscribes an event handler to a specific event type
func (eb *EventBus) Subscribe(eventType string, handler EventHandler) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.handlers[eventType] = append(eb.handlers[eventType], handler)

	if eb.obs != nil {
		eb.obs.Logger.Info().
			Str("event_type", eventType).
			Msg("Event handler subscribed")
	}
}

// Publish publishes a list of domain events
func (eb *EventBus) Publish(ctx context.Context, domainEvents []events.DomainEvent) error {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	for _, event := range domainEvents {
		if err := eb.publishEvent(ctx, event); err != nil {
			return fmt.Errorf("failed to publish event %s: %w", event.EventType(), err)
		}
	}

	return nil
}

// PublishEvent publishes a single domain event
func (eb *EventBus) PublishEvent(ctx context.Context, event events.DomainEvent) error {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	return eb.publishEvent(ctx, event)
}

// publishEvent is the internal method to publish an event
func (eb *EventBus) publishEvent(ctx context.Context, event events.DomainEvent) error {
	eventType := event.EventType()
	handlers, exists := eb.handlers[eventType]

	if !exists {
		// No handlers for this event type, log and continue
		if eb.obs != nil {
			eb.obs.Logger.Debug().
				Str("event_type", eventType).
				Str("event_id", event.EventID()).
				Msg("No handlers registered for event type")
		}
		return nil
	}

	if eb.obs != nil {
		eb.obs.Logger.Info().
			Str("event_type", eventType).
			Str("event_id", event.EventID()).
			Str("aggregate_id", event.AggregateID()).
			Int("handler_count", len(handlers)).
			Msg("Publishing domain event")
	}

	// Execute all handlers for this event type
	var lastErr error
	for i, handler := range handlers {
		if err := handler(ctx, event); err != nil {
			lastErr = err
			if eb.obs != nil {
				eb.obs.Logger.Error().
					Err(err).
					Str("event_type", eventType).
					Str("event_id", event.EventID()).
					Int("handler_index", i).
					Msg("Event handler failed")
			}
			// Continue with other handlers even if one fails
		}
	}

	if eb.obs != nil {
		eb.obs.Logger.Info().
			Str("event_type", eventType).
			Str("event_id", event.EventID()).
			Msg("Domain event published successfully")
	}

	return lastErr
}

// GetSubscriberCount returns the number of subscribers for a given event type
func (eb *EventBus) GetSubscriberCount(eventType string) int {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	handlers, exists := eb.handlers[eventType]
	if !exists {
		return 0
	}
	return len(handlers)
}

// GetEventTypes returns all registered event types
func (eb *EventBus) GetEventTypes() []string {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	var types []string
	for eventType := range eb.handlers {
		types = append(types, eventType)
	}
	return types
}

// Clear removes all event handlers (useful for testing)
func (eb *EventBus) Clear() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.handlers = make(map[string][]EventHandler)

	if eb.obs != nil {
		eb.obs.Logger.Info().Msg("Event bus cleared")
	}
}