package httpserver

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/colzphml/pkce_istio_external/internal/netutil"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
)

// ipLimiter holds a token bucket rate limiter and tracks the last access time
// so stale entries can be evicted.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiter manages per-IP token bucket limiters for /_auth/* endpoints.
type rateLimiter struct {
	mu      sync.Mutex
	ips     map[string]*ipLimiter
	rps     rate.Limit
	burst   int
	metrics *telemetry.Metrics
}

func newRateLimiter(rps float64, burst int, metrics *telemetry.Metrics) *rateLimiter {
	rl := &rateLimiter{
		ips:     make(map[string]*ipLimiter),
		rps:     rate.Limit(rps),
		burst:   burst,
		metrics: metrics,
	}
	go rl.evictLoop()
	return rl
}

// getLimiter returns (or creates) a rate limiter for the given IP.
func (rl *rateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.ips[ip]
	if !ok {
		entry = &ipLimiter{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.ips[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.limiter
}

// evictLoop periodically removes entries that have not been seen for 5 minutes
// to prevent unbounded memory growth from unique IPs.
func (rl *rateLimiter) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-5 * time.Minute)
		for ip, entry := range rl.ips {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.ips, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware wraps next and enforces the per-IP rate limit.
// route is used only for labeling the Prometheus counter.
func (rl *rateLimiter) Middleware(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.getLimiter(ip).Allow() {
			rl.metrics.RateLimitedTotal.WithLabelValues(route).Inc()
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP extracts the real client IP from X-Forwarded-For (first value) or
// falls back to the direct remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return netutil.HostOnly(xff)
	}
	return netutil.HostOnly(r.RemoteAddr)
}
