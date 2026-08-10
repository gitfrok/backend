package bus_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gitfrok/backend/platform/bus"
)

// stubEvent is a minimal Event used to exercise delivery semantics without pulling a module in.
// Its name is a constant, like every real contracts/events mirror.
type stubEvent struct {
	tenant string
	seq    int
}

func (stubEvent) EventName() string { return "test.Stub" }
func (e stubEvent) Tenant() string  { return e.tenant }

// otherEvent proves handlers are keyed by name, not by Go type.
type otherEvent struct{ tenant string }

func (otherEvent) EventName() string { return "test.Other" }
func (e otherEvent) Tenant() string  { return e.tenant }

func ev(seq int) stubEvent { return stubEvent{tenant: "t-1", seq: seq} }

// TestPublishDeliversToEverySubscriber covers AC1: a typed publish reaches every handler
// registered for that event name, in registration order, synchronously.
func TestPublishDeliversToEverySubscriber(t *testing.T) {
	b := bus.NewInProcess()
	var order []string
	b.Subscribe("test.Stub", func(context.Context, bus.Event) error {
		order = append(order, "first")
		return nil
	})
	b.Subscribe("test.Stub", func(context.Context, bus.Event) error {
		order = append(order, "second")
		return nil
	})

	if err := b.Publish(t.Context(), ev(1)); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	// Synchronous delivery: the handlers have already run when Publish returns. A consumer that
	// needs async fan-out gets it from Redpanda after extraction, not from a goroutine here.
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Errorf("want [first second] in registration order, got %v", order)
	}
}

// TestPublishOnlyReachesMatchingName guards the routing key: a subscriber must not see events
// it did not subscribe to, which is what makes the in-process seam mirror a topic.
func TestPublishOnlyReachesMatchingName(t *testing.T) {
	b := bus.NewInProcess()
	var stubSeen, otherSeen int
	b.Subscribe("test.Stub", func(context.Context, bus.Event) error { stubSeen++; return nil })
	b.Subscribe("test.Other", func(context.Context, bus.Event) error { otherSeen++; return nil })

	if err := b.Publish(t.Context(), ev(1)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if stubSeen != 1 || otherSeen != 0 {
		t.Errorf("want stub=1 other=0, got stub=%d other=%d", stubSeen, otherSeen)
	}
}

// TestPublishWithoutSubscribersIsNoOp: choreography means a producer never knows or cares whether
// anyone is listening (invariant 17). No subscriber is not an error.
func TestPublishWithoutSubscribersIsNoOp(t *testing.T) {
	if err := bus.NewInProcess().Publish(t.Context(), ev(1)); err != nil {
		t.Errorf("publish with no subscribers should succeed, got %v", err)
	}
}

// TestEveryHandlerRunsEvenWhenOneFails: consumers are independent, so one failing consumer must
// not stop the others. All errors surface joined — a failure is never swallowed.
func TestEveryHandlerRunsEvenWhenOneFails(t *testing.T) {
	b := bus.NewInProcess()
	boom := errors.New("boom")
	var ran int
	b.Subscribe("test.Stub", func(context.Context, bus.Event) error { ran++; return boom })
	b.Subscribe("test.Stub", func(context.Context, bus.Event) error { ran++; return nil })

	err := b.Publish(t.Context(), ev(1))
	if ran != 2 {
		t.Errorf("every handler must run, got %d of 2", ran)
	}
	if !errors.Is(err, boom) {
		t.Errorf("want the handler error surfaced, got %v", err)
	}
}

// TestPublishRejectsUntenantedEvent enforces invariant 1 at the seam: there is no such thing as an
// un-tenant-scoped event, so a missing tenant fails before any consumer observes it.
func TestPublishRejectsUntenantedEvent(t *testing.T) {
	b := bus.NewInProcess()
	var seen int
	b.Subscribe("test.Stub", func(context.Context, bus.Event) error { seen++; return nil })

	err := b.Publish(t.Context(), stubEvent{tenant: ""})
	if !errors.Is(err, bus.ErrTenantRequired) {
		t.Errorf("want ErrTenantRequired, got %v", err)
	}
	if seen != 0 {
		t.Errorf("an untenanted event must not reach a consumer, got %d deliveries", seen)
	}
}

// TestPublishRejectsNilEvent: a nil event is a programmer error at a call site, not a delivery.
func TestPublishRejectsNilEvent(t *testing.T) {
	if err := bus.NewInProcess().Publish(t.Context(), nil); err == nil {
		t.Error("want an error publishing a nil event")
	}
}

// TestPublishPropagatesContext: handlers receive the caller's context so a cancelled request stops
// its own choreography rather than continuing in the background.
func TestPublishPropagatesContext(t *testing.T) {
	b := bus.NewInProcess()
	type ctxKey struct{}
	var got any
	b.Subscribe("test.Stub", func(ctx context.Context, _ bus.Event) error {
		got = ctx.Value(ctxKey{})
		return nil
	})
	ctx := context.WithValue(t.Context(), ctxKey{}, "carried")
	if err := b.Publish(ctx, ev(1)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got != "carried" {
		t.Errorf("want the caller's context passed through, got %v", got)
	}
}

// TestSubscribeTypedGivesTheHandlerAConcreteType is the AC1 "typed" half: an app layer subscribes
// to one concrete event type and never type-asserts.
func TestSubscribeTypedGivesTheHandlerAConcreteType(t *testing.T) {
	b := bus.NewInProcess()
	var got stubEvent
	bus.SubscribeTyped(b, func(_ context.Context, e stubEvent) error {
		got = e
		return nil
	})

	if err := b.Publish(t.Context(), ev(42)); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got.seq != 42 {
		t.Errorf("want the concrete event delivered, got %+v", got)
	}
}

// TestSubscribeTypedRejectsAForeignPayload: two event types must never share a name. If they did,
// the typed handler would silently receive something it cannot represent — fail loudly instead.
func TestSubscribeTypedRejectsAForeignPayload(t *testing.T) {
	b := bus.NewInProcess()
	bus.SubscribeTyped(b, func(context.Context, stubEvent) error { return nil })

	// otherEvent reports a different name; publishing it under the stub name is only reachable
	// through a name collision, which is exactly what this guards.
	err := b.Publish(t.Context(), renamed{otherEvent{tenant: "t-1"}})
	if err == nil {
		t.Error("want an error when a typed handler receives a foreign payload")
	}
}

// renamed forces a name collision for the test above: a second type claiming "test.Stub".
type renamed struct{ otherEvent }

func (renamed) EventName() string { return "test.Stub" }

// instanceNamed carries its routing key in a field, so its zero value has no name. SubscribeTyped
// cannot register such a type — it reads the key from the zero value — and must say so.
type instanceNamed struct{ name string }

func (e instanceNamed) EventName() string { return e.name }
func (instanceNamed) Tenant() string      { return "t-1" }

// TestSubscribeTypedRejectsAnInstanceDependentName pins the constraint that makes zero-value key
// derivation safe: an event type's name is a constant, exactly as a Redpanda topic is. Without
// this guard the subscription would register under "" and silently never fire.
func TestSubscribeTypedRejectsAnInstanceDependentName(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("want a panic for an event type whose zero value has no name")
		}
	}()
	bus.SubscribeTyped(bus.NewInProcess(), func(context.Context, instanceNamed) error { return nil })
}

// TestSubscribeRejectsInvalidRegistration: wiring mistakes surface at startup, in cmd/, not as a
// silently dead subscription discovered in production.
func TestSubscribeRejectsInvalidRegistration(t *testing.T) {
	cases := []struct {
		name string
		call func(b *bus.InProcess)
	}{
		{"empty event name", func(b *bus.InProcess) { b.Subscribe("", func(context.Context, bus.Event) error { return nil }) }},
		{"nil handler", func(b *bus.InProcess) { b.Subscribe("test.Stub", nil) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("want a panic on an invalid subscription")
				}
			}()
			tc.call(bus.NewInProcess())
		})
	}
}

// TestConcurrentUseIsSafe: the bus is shared by every module in the plane binary, so publish and
// subscribe must be safe from many goroutines. Run with -race in CI.
func TestConcurrentUseIsSafe(t *testing.T) {
	b := bus.NewInProcess()
	var mu sync.Mutex
	var seen int
	b.Subscribe("test.Stub", func(context.Context, bus.Event) error {
		mu.Lock()
		seen++
		mu.Unlock()
		return nil
	})

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { _ = b.Publish(t.Context(), ev(1)) })
		wg.Go(func() {
			b.Subscribe("test.Late", func(context.Context, bus.Event) error { return nil })
		})
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if seen != 50 {
		t.Errorf("want 50 deliveries, got %d", seen)
	}
}

// TestHandlerMayPublish: a consumer reacting by emitting its own event must not deadlock on the
// bus lock — the common choreography shape (invariant 17).
func TestHandlerMayPublish(t *testing.T) {
	b := bus.NewInProcess()
	var chained bool
	b.Subscribe("test.Stub", func(ctx context.Context, _ bus.Event) error {
		return b.Publish(ctx, otherEvent{tenant: "t-1"})
	})
	b.Subscribe("test.Other", func(context.Context, bus.Event) error { chained = true; return nil })

	done := make(chan error, 1)
	go func() { done <- b.Publish(t.Context(), ev(1)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Publish: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("re-entrant publish deadlocked")
	}
	if !chained {
		t.Error("want the chained event delivered")
	}
}

// Bus is the port every module's app layer depends on; the concrete type must satisfy it.
var _ bus.Bus = (*bus.InProcess)(nil)
