// Package events provides domain events for the MVP Zero Trust Auth system.
// Domain events represent important business occurrences that other parts of the system should know about.
package events

import (
	"time"

	"github.com/google/uuid"
)

// DomainEvent represents a domain event
type DomainEvent interface {
	// EventID returns the unique identifier for this event
	EventID() string
	// EventType returns the type of the event
	EventType() string
	// AggregateID returns the ID of the aggregate that generated this event
	AggregateID() string
	// OccurredAt returns when the event occurred
	OccurredAt() time.Time
	// EventData returns the event data as a map
	EventData() map[string]interface{}
}

// BaseEvent provides common functionality for domain events
type BaseEvent struct {
	id          string
	eventType   string
	aggregateID string
	occurredAt  time.Time
	data        map[string]interface{}
}

// NewBaseEvent creates a new base event
func NewBaseEvent(eventType, aggregateID string, data map[string]interface{}) BaseEvent {
	return BaseEvent{
		id:          uuid.New().String(),
		eventType:   eventType,
		aggregateID: aggregateID,
		occurredAt:  time.Now(),
		data:        data,
	}
}

// EventID returns the unique identifier for this event
func (e BaseEvent) EventID() string {
	return e.id
}

// EventType returns the type of the event
func (e BaseEvent) EventType() string {
	return e.eventType
}

// AggregateID returns the ID of the aggregate that generated this event
func (e BaseEvent) AggregateID() string {
	return e.aggregateID
}

// OccurredAt returns when the event occurred
func (e BaseEvent) OccurredAt() time.Time {
	return e.occurredAt
}

// EventData returns the event data as a map
func (e BaseEvent) EventData() map[string]interface{} {
	return e.data
}
