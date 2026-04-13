// Package circuitbreaker provides a minimal three-state circuit breaker that
// can wrap any fallible operation.
//
// States:
//   - Closed  – normal operation; failures are counted.
//   - Open    – fast-fail; no requests pass through until Timeout elapses.
//   - HalfOpen – one probe request is allowed through; success closes, failure
//     re-opens.
package circuitbreaker

import (
	"errors"
	"sync"
	"time"
)

// ErrOpen is returned when the circuit is open and the request is rejected
// without being attempted.
var ErrOpen = errors.New("circuit breaker is open")

// State represents the current state of the circuit breaker.
type State int

const (
	StateClosed   State = iota // normal operation
	StateHalfOpen              // one trial request allowed
	StateOpen                  // fast-fail
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateHalfOpen:
		return "half-open"
	case StateOpen:
		return "open"
	default:
		return "unknown"
	}
}

// CircuitBreaker is a concurrency-safe three-state circuit breaker.
type CircuitBreaker struct {
	mu          sync.Mutex
	state       State
	failures    int
	maxFailures int
	timeout     time.Duration
	openedAt    time.Time
	onStateChange func(from, to State)
}

// New creates a circuit breaker that opens after maxFailures consecutive
// failures and attempts recovery after timeout. If maxFailures is 0 or
// negative, the circuit breaker is disabled (always closed).
func New(maxFailures int, timeout time.Duration, onStateChange func(from, to State)) *CircuitBreaker {
	return &CircuitBreaker{
		state:         StateClosed,
		maxFailures:   maxFailures,
		timeout:       timeout,
		onStateChange: onStateChange,
	}
}

// Execute runs fn inside the circuit breaker.
//   - If the circuit is open, it returns ErrOpen immediately.
//   - If fn returns a non-nil error, the failure counter is incremented.
//   - After maxFailures consecutive failures the circuit opens.
//   - In HalfOpen state only one call is let through at a time.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if cb.maxFailures <= 0 {
		return fn()
	}

	cb.mu.Lock()
	switch cb.state {
	case StateOpen:
		if time.Since(cb.openedAt) < cb.timeout {
			cb.mu.Unlock()
			return ErrOpen
		}
		cb.transition(StateHalfOpen)
	case StateHalfOpen:
		// Only one probe at a time; reject additional callers.
		cb.mu.Unlock()
		return ErrOpen
	}
	cb.mu.Unlock()

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		if cb.state == StateHalfOpen || cb.failures >= cb.maxFailures {
			cb.transition(StateOpen)
		}
		return err
	}

	cb.failures = 0
	if cb.state == StateHalfOpen {
		cb.transition(StateClosed)
	}
	return nil
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

func (cb *CircuitBreaker) transition(to State) {
	from := cb.state
	cb.state = to
	if to == StateOpen {
		cb.openedAt = time.Now()
		cb.failures = 0
	}
	if cb.onStateChange != nil && from != to {
		cb.onStateChange(from, to)
	}
}
