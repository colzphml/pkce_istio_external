package telemetry

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	Registry            *prometheus.Registry
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	AuthzChecksTotal    *prometheus.CounterVec
	AuthzCheckDuration  prometheus.Histogram
	RefreshTotal        *prometheus.CounterVec
	LoginTotal          *prometheus.CounterVec
	LogoutTotal         *prometheus.CounterVec
	BackchannelTotal    *prometheus.CounterVec
}

func New() *Metrics {
	registry := prometheus.NewRegistry()
	m := &Metrics{
		Registry: registry,
		HTTPRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "oidc_auth",
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests processed by the auth service.",
		}, []string{"route", "method", "code"}),
		HTTPRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "oidc_auth",
			Name:      "http_request_duration_seconds",
			Help:      "Latency of HTTP requests handled by the auth service.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"route", "method"}),
		AuthzChecksTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "oidc_auth",
			Name:      "ext_authz_checks_total",
			Help:      "Total number of ext_authz checks by decision.",
		}, []string{"decision"}),
		AuthzCheckDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "oidc_auth",
			Name:      "ext_authz_check_duration_seconds",
			Help:      "Latency of ext_authz checks.",
			Buckets:   prometheus.DefBuckets,
		}),
		RefreshTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "oidc_auth",
			Name:      "refresh_total",
			Help:      "Refresh attempts by outcome.",
		}, []string{"result"}),
		LoginTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "oidc_auth",
			Name:      "login_total",
			Help:      "Login flow events by outcome.",
		}, []string{"result"}),
		LogoutTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "oidc_auth",
			Name:      "logout_total",
			Help:      "Logout flow events by outcome.",
		}, []string{"result"}),
		BackchannelTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "oidc_auth",
			Name:      "backchannel_logout_total",
			Help:      "Backchannel logout events by outcome.",
		}, []string{"result"}),
	}

	registry.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.AuthzChecksTotal,
		m.AuthzCheckDuration,
		m.RefreshTotal,
		m.LoginTotal,
		m.LogoutTotal,
		m.BackchannelTotal,
	)

	return m
}

func (m *Metrics) InstrumentHTTP(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)

		code := strconv.Itoa(rec.status)
		m.HTTPRequestsTotal.WithLabelValues(route, r.Method, code).Inc()
		m.HTTPRequestDuration.WithLabelValues(route, r.Method).Observe(time.Since(start).Seconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
