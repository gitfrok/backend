// Package bus is the in-process event bus (ADR-0025). Cross-module, in-process communication
// goes through here or a module's api/ package — never internal/*.
//
// The seam deliberately mirrors what Redpanda gives us across processes (ADR-0022), so promoting
// a module to its own service (ADR-0026) is a transport swap and not a caller change:
//
//   - the routing key is the event's fully-qualified name, which mirrors the protobuf message
//     name in governance/contracts/events — the same string a Redpanda topic keys off;
//   - producers never learn who consumes them, so adding a consumer is not a producer change
//     (invariant 17);
//   - every event is tenant-scoped (invariant 1), enforced here rather than per consumer.
//
// Delivery is synchronous and ordered within a single Publish. That is a deliberate limit of the
// in-process stage: it keeps a request's choreography inside the request's own context and
// transaction. Anything needing at-least-once redelivery or replay belongs on Redpanda already,
// not on a goroutine behind this interface.
package bus

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Event is any domain event published to the bus. Both methods mirror fields present on every
// message in contracts/events: the message's full name and its tenant_id.
type Event interface {
	// EventName is the routing key — the fully-qualified protobuf message name of the
	// contracts/events schema this event mirrors.
	EventName() string
	// Tenant is the owning tenant. Never empty; the bus rejects an event without one.
	Tenant() string
}

// Handler consumes one delivered event.
type Handler func(context.Context, Event) error

// Bus publishes and subscribes to in-process domain events. Modules depend on this interface;
// cmd/ injects the concrete implementation (ADR-0025).
type Bus interface {
	Publish(ctx context.Context, e Event) error
	Subscribe(name string, h Handler)
}

// ErrTenantRequired is returned when an event carries no tenant. There is no un-tenant-scoped
// event: a consumer that cannot scope what it received cannot honour invariant 1.
var ErrTenantRequired = errors.New("bus: event has no tenant")

// InProcess is the single-process Bus used inside a plane binary.
type InProcess struct {
	mu       sync.RWMutex
	handlers map[string][]Handler
}

// NewInProcess builds an empty in-process bus.
func NewInProcess() *InProcess {
	return &InProcess{handlers: make(map[string][]Handler)}
}

// Subscribe registers h for every event published under name. Registration happens at wiring
// time in cmd/, so an invalid registration is a programmer error and panics rather than
// producing a subscription that silently never fires.
func (b *InProcess) Subscribe(name string, h Handler) {
	if name == "" {
		panic("bus: Subscribe with an empty event name")
	}
	if h == nil {
		panic("bus: Subscribe with a nil handler for " + name)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[name] = append(b.handlers[name], h)
}

// Publish delivers e to every handler subscribed to its name, in registration order, and returns
// once they have all run. Every handler runs even if an earlier one fails — consumers are
// independent — and the failures come back joined so none is swallowed.
func (b *InProcess) Publish(ctx context.Context, e Event) error {
	if e == nil {
		return errors.New("bus: publish of a nil event")
	}
	name := e.EventName()
	if name == "" {
		return errors.New("bus: event has no name")
	}
	if e.Tenant() == "" {
		return fmt.Errorf("publishing %s: %w", name, ErrTenantRequired)
	}

	// Copy under a read lock and invoke outside it, so a handler is free to publish (the common
	// choreography shape) without deadlocking on the bus.
	b.mu.RLock()
	hs := make([]Handler, len(b.handlers[name]))
	copy(hs, b.handlers[name])
	b.mu.RUnlock()

	var errs []error
	for _, h := range hs {
		if err := h(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("handling %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// SubscribeTyped registers a handler for one concrete event type, so an app layer subscribes
// without type-asserting.
//
// The routing key is read from T's zero value, so T must be the value type carrying the methods
// (not a pointer) and its EventName must be a constant — true of every contracts/events mirror,
// and the reason the key is stable enough to be a topic name. An event type that derives its name
// from instance state would register under "" and never fire, so it panics here instead.
func SubscribeTyped[T Event](b Bus, h func(context.Context, T) error) {
	var zero T
	name := zero.EventName()
	if name == "" {
		panic(fmt.Sprintf("bus: SubscribeTyped[%T]: EventName must be a constant, not derived from instance state", zero))
	}
	b.Subscribe(name, func(ctx context.Context, e Event) error {
		typed, ok := e.(T)
		if !ok {
			// Only reachable if two event types claim the same name, which would also collide
			// on a Redpanda topic. Fail loudly rather than dropping the event.
			return fmt.Errorf("bus: handler for %s got %T", name, e)
		}
		return h(ctx, typed)
	})
}
