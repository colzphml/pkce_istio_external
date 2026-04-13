package circuitbreaker

import (
	"errors"
	"testing"
	"time"
)

var errFake = errors.New("fake error")

func TestCircuitBreaker_Disabled(t *testing.T) {
	cb := New(0, time.Second, nil)
	called := false
	err := cb.Execute(func() error { called = true; return errFake })
	if !called {
		t.Fatal("Execute() did not call fn when circuit breaker is disabled")
	}
	if !errors.Is(err, errFake) {
		t.Fatalf("Execute() error = %v, want errFake", err)
	}
}

func TestCircuitBreaker_OpensAfterMaxFailures(t *testing.T) {
	cb := New(3, 10*time.Second, nil)

	for range 3 {
		if st := cb.State(); st != StateClosed {
			t.Fatalf("before max failures: state = %s, want closed", st)
		}
		_ = cb.Execute(func() error { return errFake })
	}

	if st := cb.State(); st != StateOpen {
		t.Fatalf("after max failures: state = %s, want open", st)
	}
}

func TestCircuitBreaker_FastFailWhenOpen(t *testing.T) {
	cb := New(1, 10*time.Second, nil)
	_ = cb.Execute(func() error { return errFake })

	called := false
	err := cb.Execute(func() error { called = true; return nil })
	if called {
		t.Fatal("Execute() called fn when circuit is open")
	}
	if !errors.Is(err, ErrOpen) {
		t.Fatalf("Execute() error = %v, want ErrOpen", err)
	}
}

func TestCircuitBreaker_HalfOpenOnTimeout(t *testing.T) {
	cb := New(1, 10*time.Millisecond, nil)
	_ = cb.Execute(func() error { return errFake })

	time.Sleep(20 * time.Millisecond)

	// The first call after timeout should be attempted (half-open probe).
	called := false
	_ = cb.Execute(func() error { called = true; return nil })
	if !called {
		t.Fatal("Execute() did not allow probe after timeout")
	}

	if st := cb.State(); st != StateClosed {
		t.Fatalf("after successful probe: state = %s, want closed", st)
	}
}

func TestCircuitBreaker_ReOpensOnHalfOpenFailure(t *testing.T) {
	cb := New(1, 10*time.Millisecond, nil)
	_ = cb.Execute(func() error { return errFake })

	time.Sleep(20 * time.Millisecond)

	// Probe fails → re-open.
	_ = cb.Execute(func() error { return errFake })

	if st := cb.State(); st != StateOpen {
		t.Fatalf("after probe failure: state = %s, want open", st)
	}
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	cb := New(3, time.Second, nil)

	// Two failures.
	_ = cb.Execute(func() error { return errFake })
	_ = cb.Execute(func() error { return errFake })

	// One success — resets counter.
	_ = cb.Execute(func() error { return nil })

	// Now need 3 more failures to open.
	_ = cb.Execute(func() error { return errFake })
	_ = cb.Execute(func() error { return errFake })
	if st := cb.State(); st == StateOpen {
		t.Fatal("circuit opened too early: failure count should have been reset")
	}

	_ = cb.Execute(func() error { return errFake })
	if st := cb.State(); st != StateOpen {
		t.Fatalf("circuit should be open after 3 consecutive failures, got %s", st)
	}
}

func TestCircuitBreaker_StateChangeCallback(t *testing.T) {
	var changes []string
	cb := New(1, 10*time.Millisecond, func(from, to State) {
		changes = append(changes, from.String()+"->"+to.String())
	})

	_ = cb.Execute(func() error { return errFake })
	time.Sleep(20 * time.Millisecond)
	_ = cb.Execute(func() error { return nil })

	// closed->open and open->half-open and half-open->closed
	if len(changes) < 2 {
		t.Fatalf("expected at least 2 state changes, got %v", changes)
	}
}
