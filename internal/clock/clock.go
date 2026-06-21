// Package clock provides a time-source abstraction used across all authcore modules.
//
// Every module that performs time-sensitive work (token expiry, issuance
// timestamps, rate-limit windows) must depend on Clock rather than calling
// time.Now() directly. This keeps modules decoupled from wall-clock time and
// makes them straightforward to test without real sleeps or time.Sleep hacks.
//
// Usage inside a module:
//
//	clk := clock.New(provider.Config().Timezone)
//	now := clk.Now()
package clock

import "time"

// Clock is a source of current time. Inject this into any struct that needs
// to reason about time so tests can substitute a controlled implementation.
type Clock interface {
	// Now returns the current time in the Clock's configured location.
	Now() time.Time
}

// New returns a Clock backed by the real wall clock.
//
// loc controls the time.Location applied to every returned time value,
// ensuring all modules honour the timezone configured by the library user.
// If loc is nil, time.UTC is used as a safe fallback.
func New(loc *time.Location) Clock {
	if loc == nil {
		loc = time.UTC
	}
	return &realClock{loc: loc}
}

// realClock is the production Clock implementation.
type realClock struct {
	loc *time.Location
}

func (c *realClock) Now() time.Time {
	return time.Now().In(c.loc)
}

// Fixed returns a Clock that always returns t regardless of wall-clock time.
// Use this in tests to control the current time without real sleeps.
//
//	clk := clock.Fixed(time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC))
//	now := clk.Now() // always 2024-01-15T12:00:00Z
func Fixed(t time.Time) Clock {
	return fixedClock{t: t}
}

// fixedClock is a Clock that always returns the same instant.
type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }
