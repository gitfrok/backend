// Package bus is the in-process event bus seam (ADR-0025). Cross-module, in-process
// communication goes through here or a module's api/ package — never internal/*.
// The real implementation lands in T-0008; this is the port only.
package bus

import "context"

// Event is any domain event published to the bus (mirrors contracts/events schemas).
type Event interface{ EventName() string }

// Bus publishes and subscribes to in-process domain events.
type Bus interface {
	Publish(ctx context.Context, e Event) error
	Subscribe(name string, h func(context.Context, Event) error)
}
