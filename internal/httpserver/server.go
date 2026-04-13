package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/colzphml/pkce_istio_external/internal/config"
	"github.com/colzphml/pkce_istio_external/internal/netutil"
	"github.com/colzphml/pkce_istio_external/internal/session"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
	"github.com/colzphml/pkce_istio_external/internal/version"
)

type Server struct {
	httpServer *http.Server
	manager    *session.Manager
	cfg        config.Config
	logger     *slog.Logger
	metrics    *telemetry.Metrics
}

func New(addr string, manager *session.Manager, cfg config.Config, logger *slog.Logger, metrics *telemetry.Metrics, readiness func() error) *Server {
	s := &Server{
		manager: manager,
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
	}

	// Build the per-IP rate limiter for /_auth/* endpoints.
	// When RateLimitRPS is 0 (or negative) rate limiting is disabled.
	var rl *rateLimiter
	if cfg.Server.RateLimitRPS > 0 {
		rl = newRateLimiter(cfg.Server.RateLimitRPS, cfg.Server.RateLimitBurst, metrics)
	}
	rateLimit := func(route string, h http.Handler) http.Handler {
		if rl == nil {
			return h
		}
		return rl.Middleware(route, h)
	}

	router := chi.NewRouter()
	router.Get(cfg.OIDC.LoginPath, rateLimit("login", metrics.InstrumentHTTP("login", http.HandlerFunc(s.handleLogin))).ServeHTTP)
	router.Get(cfg.OIDC.CallbackPath, rateLimit("callback", metrics.InstrumentHTTP("callback", http.HandlerFunc(s.handleCallback))).ServeHTTP)
	router.MethodFunc(http.MethodGet, cfg.OIDC.LogoutPath, rateLimit("logout", http.HandlerFunc(s.handleLogout)).ServeHTTP)
	router.MethodFunc(http.MethodPost, cfg.OIDC.LogoutPath, rateLimit("logout", http.HandlerFunc(s.handleLogout)).ServeHTTP)
	router.Post(cfg.OIDC.BackchannelPath, rateLimit("backchannel_logout", metrics.InstrumentHTTP("backchannel_logout", http.HandlerFunc(s.handleBackchannelLogout))).ServeHTTP)
	router.Get("/healthz", metrics.InstrumentHTTP("healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})).ServeHTTP)
	router.Get("/readyz", metrics.InstrumentHTTP("readyz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := readiness(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})).ServeHTTP)
	router.Get("/versionz", metrics.InstrumentHTTP("versionz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(version.Current()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})).ServeHTTP)
	router.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		BaseContext: func(listener net.Listener) context.Context {
			return context.Background()
		},
	}

	return s
}

func (s *Server) HTTPServer() *http.Server {
	return s.httpServer
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	origin, err := originFromRequest(r, s.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	if cookie, err := r.Cookie(s.cfg.Session.CookieName); err == nil {
		if sess, err := s.manager.GetSession(r.Context(), cookie.Value); err == nil {
			if fresh, err := s.manager.EnsureFresh(r.Context(), sess); err == nil && fresh != nil {
				http.Redirect(w, r, normalizeReturnPath(r.URL.Query().Get("return_url")), http.StatusFound)
				return
			}
		}
	}

	redirectURL, err := s.manager.BeginLogin(r.Context(), origin, r.URL.Query().Get("return_url"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if oidcError := r.URL.Query().Get("error"); oidcError != "" {
		http.Error(w, oidcError, http.StatusUnauthorized)
		return
	}

	origin, err := originFromRequest(r, s.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	sess, returnPath, err := s.manager.CompleteLogin(r.Context(), origin, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, session.ErrStateNotFound) {
			status = http.StatusUnauthorized
		}
		http.Error(w, err.Error(), status)
		return
	}

	http.SetCookie(w, s.manager.SessionCookie(sess.ID))
	http.Redirect(w, r, returnPath, http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// CSRF protection for POST logout: verify that the Origin header (when present)
	// belongs to an allowed host. GET requests are not subject to this check because
	// browsers do not send Origin on plain navigation. If Origin is absent on POST
	// we still allow the request for API clients that may omit the header.
	if r.Method == http.MethodPost {
		if originHeader := strings.TrimSpace(r.Header.Get("Origin")); originHeader != "" {
			if !originAllowed(originHeader, s.cfg) {
				http.Error(w, "cross-origin logout not allowed", http.StatusForbidden)
				return
			}
		}
	}

	origin, err := originFromRequest(r, s.cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	sessionID := ""
	if cookie, err := r.Cookie(s.cfg.Session.CookieName); err == nil {
		sessionID = cookie.Value
	}

	redirectURL, err := s.manager.Logout(r.Context(), origin, sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.SetCookie(w, s.manager.ClearSessionCookie())
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (s *Server) handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rawLogoutToken := strings.TrimSpace(r.FormValue("logout_token"))
	if rawLogoutToken == "" {
		http.Error(w, "logout_token is required", http.StatusBadRequest)
		return
	}

	deleted, err := s.manager.BackchannelLogout(r.Context(), rawLogoutToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"deleted_sessions":%d}`, deleted)
}

// originAllowed reports whether the raw Origin header value (e.g.
// "https://app.example.com") refers to a host in cfg.Session.AllowedHosts.
func originAllowed(rawOrigin string, cfg config.Config) bool {
	parsed, err := url.Parse(rawOrigin)
	if err != nil {
		return false
	}
	host := netutil.HostOnly(parsed.Host)
	if host == "" {
		return false
	}
	if len(cfg.Session.AllowedHosts) == 0 {
		return true
	}
	for _, item := range cfg.Session.AllowedHosts {
		item = netutil.HostOnly(item)
		if item == host || (strings.HasPrefix(item, "*.") && strings.HasSuffix(host, strings.TrimPrefix(item, "*"))) {
			return true
		}
	}
	return false
}

func originFromRequest(r *http.Request, cfg config.Config) (string, error) {
	scheme := headerOrDefault(r.Header, "X-Forwarded-Proto", "http")
	host := headerOrDefault(r.Header, "X-Forwarded-Host", r.Host)
	host = netutil.HostOnly(host)
	if host == "" {
		return "", errors.New("missing host")
	}

	allowed := len(cfg.Session.AllowedHosts) == 0
	for _, item := range cfg.Session.AllowedHosts {
		item = netutil.HostOnly(item)
		if item == host || (strings.HasPrefix(item, "*.") && strings.HasSuffix(host, strings.TrimPrefix(item, "*"))) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", session.ErrInvalidHost
	}

	return scheme + "://" + host, nil
}

func normalizeReturnPath(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "/"
	}
	if !strings.HasPrefix(raw, "/") {
		return "/"
	}
	if raw == "/_auth" || strings.HasPrefix(raw, "/_auth/") {
		return "/"
	}
	return raw
}

func headerOrDefault(headers http.Header, key, fallback string) string {
	value := strings.TrimSpace(headers.Get(key))
	if value == "" {
		return fallback
	}
	return value
}

