package testutil

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/colzphml/pkce_istio_external/internal/config"
	"github.com/colzphml/pkce_istio_external/internal/model"
	"github.com/colzphml/pkce_istio_external/internal/oidc"
	"github.com/colzphml/pkce_istio_external/internal/store"
)

type FixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func NewFixedClock(now time.Time) *FixedClock {
	return &FixedClock{now: now}
}

func (c *FixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *FixedClock) Sleep(ctx context.Context, d time.Duration) error {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

type FakeOIDCClient struct {
	AuthBaseURL      string
	ExchangeToken    *oidc.TokenSet
	ExchangeIdentity *oidc.Identity
	ExchangeErr      error
	RefreshToken     *oidc.TokenSet
	RefreshErr       error
	LogoutURL        string
	LogoutErr        error
	LogoutToken      *oidc.LogoutToken
	VerifyLogoutErr  error

	LastAuthState       string
	LastAuthNonce       string
	LastAuthRedirectURL string
	LastAuthVerifier    string
	RefreshCalls        int
}

func (f *FakeOIDCClient) AuthCodeURL(state, nonce, redirectURL, codeVerifier string) string {
	f.LastAuthState = state
	f.LastAuthNonce = nonce
	f.LastAuthRedirectURL = redirectURL
	f.LastAuthVerifier = codeVerifier

	base := f.AuthBaseURL
	if base == "" {
		base = "https://keycloak.example.com/auth"
	}
	parsed, _ := url.Parse(base)
	query := parsed.Query()
	query.Set("state", state)
	query.Set("redirect_uri", redirectURL)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (f *FakeOIDCClient) ExchangeCode(context.Context, string, string, string) (*oidc.TokenSet, *oidc.Identity, error) {
	if f.ExchangeErr != nil {
		return nil, nil, f.ExchangeErr
	}
	return f.ExchangeToken, f.ExchangeIdentity, nil
}

func (f *FakeOIDCClient) Refresh(context.Context, string) (*oidc.TokenSet, error) {
	f.RefreshCalls++
	if f.RefreshErr != nil {
		return nil, f.RefreshErr
	}
	return f.RefreshToken, nil
}

func (f *FakeOIDCClient) VerifyIDTokenNonce(identity *oidc.Identity, expectedNonce string) error {
	if identity == nil {
		return fmt.Errorf("identity is nil")
	}
	if identity.Nonce != expectedNonce {
		return fmt.Errorf("nonce mismatch")
	}
	return nil
}

func (f *FakeOIDCClient) BuildLogoutURL(string, string) (string, error) {
	if f.LogoutErr != nil {
		return "", f.LogoutErr
	}
	if f.LogoutURL == "" {
		return "https://keycloak.example.com/logout", nil
	}
	return f.LogoutURL, nil
}

func (f *FakeOIDCClient) VerifyLogoutToken(context.Context, string) (*oidc.LogoutToken, error) {
	if f.VerifyLogoutErr != nil {
		return nil, f.VerifyLogoutErr
	}
	return f.LogoutToken, nil
}

type MemoryStore struct {
	mu       sync.Mutex
	states   map[string]model.LoginState
	sessions map[string]model.Session
	locks    map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		states:   make(map[string]model.LoginState),
		sessions: make(map[string]model.Session),
		locks:    make(map[string]string),
	}
}

func (s *MemoryStore) Ping(context.Context) error { return nil }

func (s *MemoryStore) SaveLoginState(_ context.Context, state model.LoginState, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
	return nil
}

func (s *MemoryStore) ConsumeLoginState(_ context.Context, key string) (*model.LoginState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.states[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	delete(s.states, key)
	return &state, nil
}

func (s *MemoryStore) SaveSession(_ context.Context, sess model.Session, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

func (s *MemoryStore) GetSession(_ context.Context, id string) (*model.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return &sess, nil
}

func (s *MemoryStore) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
	return nil
}

func (s *MemoryStore) DeleteSessionsByKCSessionID(_ context.Context, kcSessionID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for id, sess := range s.sessions {
		if sess.KCSessionID == kcSessionID {
			delete(s.sessions, id)
			deleted++
		}
	}
	return deleted, nil
}

func (s *MemoryStore) AcquireRefreshLock(_ context.Context, sessionID, owner string, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.locks[sessionID]; exists {
		return false, nil
	}
	s.locks[sessionID] = owner
	return true, nil
}

func (s *MemoryStore) ReleaseRefreshLock(_ context.Context, sessionID, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if currentOwner, exists := s.locks[sessionID]; exists && currentOwner == owner {
		delete(s.locks, sessionID)
	}
	return nil
}

func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func BaseConfig(now time.Time) config.Config {
	return config.Config{
		Log: config.LogConfig{Level: "debug"},
		Server: config.ServerConfig{
			HTTPAddr:        ":8080",
			GRPCAddr:        ":9090",
			ReadTimeout:     5 * time.Second,
			WriteTimeout:    5 * time.Second,
			IdleTimeout:     30 * time.Second,
			ShutdownTimeout: 10 * time.Second,
		},
		OIDC: config.OIDCConfig{
			IssuerURL:            "https://keycloak.example.com/realms/main",
			ClientID:             "oidc-auth",
			ClientSecret:         "secret",
			Scopes:               []string{"openid", "profile", "email", "offline_access"},
			CallbackPath:         "/_auth/callback",
			LogoutPath:           "/_auth/logout",
			PostLogoutPath:       "/",
			BackchannelPath:      "/_auth/backchannel-logout",
			LoginPath:            "/_auth/login",
			LoginStateTTL:        10 * time.Minute,
			RefreshWindow:        2 * time.Minute,
			HTTPTimeout:          5 * time.Second,
			ClockSkew:            30 * time.Second,
			AccessTokenAudiences: []string{"oidc-auth"},
		},
		Redis: config.RedisConfig{
			Mode:             "standalone",
			Addresses:        []string{"127.0.0.1:6379"},
			KeyPrefix:        "oidc:",
			DialTimeout:      2 * time.Second,
			ReadTimeout:      2 * time.Second,
			WriteTimeout:     2 * time.Second,
			PoolSize:         32,
			MinIdleConns:     8,
			LockRefreshTTL:   5 * time.Second,
			LockWaitTimeout:  500 * time.Millisecond,
			LockPollInterval: 10 * time.Millisecond,
		},
		Session: config.SessionConfig{
			CookieName:        "__Host-oidc_session",
			CookieSecure:      true,
			CookieSameSite:    "Lax",
			MaxLifetime:       12 * time.Hour,
			MinAccessTokenTTL: 10 * time.Second,
			AllowedHosts:      []string{"app.example.com"},
		},
		Headers: config.HeaderConfig{
			AuthorizationHeader:     "authorization",
			UserHeader:              "x-auth-request-user",
			EmailHeader:             "x-auth-request-email",
			SubjectHeader:           "x-auth-request-sub",
			PreferredUsernameHeader: "x-auth-request-preferred-username",
			GroupsHeader:            "x-auth-request-groups",
		},
	}
}
