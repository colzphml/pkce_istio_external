package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/colzphml/pkce_istio_external/internal/clock"
	"github.com/colzphml/pkce_istio_external/internal/config"
	"github.com/colzphml/pkce_istio_external/internal/model"
	"github.com/colzphml/pkce_istio_external/internal/oidc"
	"github.com/colzphml/pkce_istio_external/internal/store"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
)

var (
	ErrStateNotFound  = errors.New("login state not found")
	ErrInvalidHost    = errors.New("host is not allowed")
	ErrReturnPath     = errors.New("invalid return path")
	ErrSessionExpired = errors.New("session expired")
)

type Manager struct {
	store   store.Store
	oidc    OIDCClient
	cfg     config.Config
	logger  *slog.Logger
	clock   clock.Clock
	metrics *telemetry.Metrics
}

type OIDCClient interface {
	AuthCodeURL(state, nonce, redirectURL, codeVerifier string) string
	ExchangeCode(context.Context, string, string, string) (*oidc.TokenSet, *oidc.Identity, error)
	Refresh(context.Context, string) (*oidc.TokenSet, error)
	VerifyIDTokenNonce(*oidc.Identity, string) error
	BuildLogoutURL(string, string) (string, error)
	VerifyLogoutToken(context.Context, string) (*oidc.LogoutToken, error)
}

type SessionIdentity struct {
	AuthorizationValue     string
	UserHeaderValue        string
	EmailHeaderValue       string
	SubjectHeaderValue     string
	PreferredUsernameValue string
	GroupsHeaderValue      string
}

func NewManager(cfg config.Config, store store.Store, oidcClient OIDCClient, logger *slog.Logger, clk clock.Clock, metrics *telemetry.Metrics) *Manager {
	return &Manager{
		store:   store,
		oidc:    oidcClient,
		cfg:     cfg,
		logger:  logger,
		clock:   clk,
		metrics: metrics,
	}
}

func (m *Manager) BeginLogin(ctx context.Context, origin, returnPath string) (string, error) {
	if err := m.validateOrigin(origin); err != nil {
		m.metrics.LoginTotal.WithLabelValues("invalid_origin").Inc()
		return "", err
	}

	returnPath = m.normalizeReturnPath(returnPath)
	stateValue, err := model.RandomToken(32)
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	nonceValue, err := model.RandomToken(32)
	if err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	codeVerifier, err := model.RandomToken(64)
	if err != nil {
		return "", fmt.Errorf("generate code verifier: %w", err)
	}

	loginState := model.LoginState{
		State:        stateValue,
		Nonce:        nonceValue,
		CodeVerifier: codeVerifier,
		ReturnPath:   returnPath,
		CreatedAt:    m.clock.Now(),
	}
	if err := m.store.SaveLoginState(ctx, loginState, m.cfg.OIDC.LoginStateTTL); err != nil {
		return "", fmt.Errorf("save login state: %w", err)
	}

	m.metrics.LoginTotal.WithLabelValues("redirect").Inc()
	return m.oidc.AuthCodeURL(stateValue, nonceValue, origin+m.cfg.OIDC.CallbackPath, codeVerifier), nil
}

func (m *Manager) CompleteLogin(ctx context.Context, origin, stateValue, code string) (*model.Session, string, error) {
	if err := m.validateOrigin(origin); err != nil {
		m.metrics.LoginTotal.WithLabelValues("invalid_origin").Inc()
		return nil, "", err
	}

	loginState, err := m.store.ConsumeLoginState(ctx, stateValue)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			m.metrics.LoginTotal.WithLabelValues("state_not_found").Inc()
			return nil, "", ErrStateNotFound
		}
		return nil, "", fmt.Errorf("consume login state: %w", err)
	}

	tokenSet, identity, err := m.oidc.ExchangeCode(ctx, origin+m.cfg.OIDC.CallbackPath, code, loginState.CodeVerifier)
	if err != nil {
		m.metrics.LoginTotal.WithLabelValues("exchange_failed").Inc()
		return nil, "", err
	}
	if err := m.oidc.VerifyIDTokenNonce(identity, loginState.Nonce); err != nil {
		m.metrics.LoginTotal.WithLabelValues("nonce_mismatch").Inc()
		return nil, "", err
	}

	now := m.clock.Now()
	sessionID, err := model.RandomToken(32)
	if err != nil {
		return nil, "", fmt.Errorf("generate session id: %w", err)
	}
	sess := model.Session{
		ID:                 sessionID,
		Subject:            identity.Subject,
		Email:              identity.Email,
		PreferredUsername:  identity.PreferredUsername,
		Groups:             identity.Groups,
		KCSessionID:        identity.KCSessionID,
		AccessToken:        tokenSet.AccessToken,
		RefreshToken:       tokenSet.RefreshToken,
		IDToken:            tokenSet.IDToken,
		TokenType:          tokenSet.TokenType,
		AccessTokenExpiry:  tokenSet.AccessTokenExpiry,
		RefreshTokenExpiry: tokenSet.RefreshTokenExpiry,
		CreatedAt:          now,
		ExpiresAt:          m.sessionExpiry(now, tokenSet),
		Issuer:             identity.Issuer,
		Audience:           identity.Audience,
	}

	if err := m.store.SaveSession(ctx, sess, sess.TTL(now)); err != nil {
		return nil, "", fmt.Errorf("save session: %w", err)
	}

	m.metrics.LoginTotal.WithLabelValues("success").Inc()
	return &sess, loginState.ReturnPath, nil
}

func (m *Manager) Logout(ctx context.Context, origin, sessionID string) (string, error) {
	if err := m.validateOrigin(origin); err != nil {
		m.metrics.LogoutTotal.WithLabelValues("invalid_origin").Inc()
		return "", err
	}

	postLogoutURL := origin + m.cfg.OIDC.PostLogoutPath
	if sessionID == "" {
		m.metrics.LogoutTotal.WithLabelValues("missing_session").Inc()
		return postLogoutURL, nil
	}

	sess, err := m.store.GetSession(ctx, sessionID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("load session for logout: %w", err)
	}
	if sess == nil {
		m.metrics.LogoutTotal.WithLabelValues("missing_session").Inc()
		return postLogoutURL, nil
	}

	if sess.KCSessionID != "" {
		if _, err := m.store.DeleteSessionsByKCSessionID(ctx, sess.KCSessionID); err != nil {
			return "", fmt.Errorf("delete sessions by kc session id: %w", err)
		}
	} else if err := m.store.DeleteSession(ctx, sess.ID); err != nil {
		return "", fmt.Errorf("delete session: %w", err)
	}

	redirectURL, err := m.oidc.BuildLogoutURL(postLogoutURL, sess.IDToken)
	if err != nil {
		return "", err
	}
	m.metrics.LogoutTotal.WithLabelValues("success").Inc()
	return redirectURL, nil
}

func (m *Manager) BackchannelLogout(ctx context.Context, rawLogoutToken string) (int, error) {
	logoutToken, err := m.oidc.VerifyLogoutToken(ctx, rawLogoutToken)
	if err != nil {
		m.metrics.BackchannelTotal.WithLabelValues("invalid_token").Inc()
		return 0, err
	}

	deleted, err := m.store.DeleteSessionsByKCSessionID(ctx, logoutToken.KCSessionID)
	if err != nil {
		m.metrics.BackchannelTotal.WithLabelValues("store_error").Inc()
		return 0, err
	}

	m.metrics.BackchannelTotal.WithLabelValues("success").Inc()
	return deleted, nil
}

func (m *Manager) GetSession(ctx context.Context, sessionID string) (*model.Session, error) {
	sess, err := m.store.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrSessionExpired
		}
		return nil, err
	}

	now := m.clock.Now()
	if !sess.ExpiresAt.After(now) {
		_ = m.store.DeleteSession(ctx, sessionID)
		return nil, ErrSessionExpired
	}
	return sess, nil
}

func (m *Manager) EnsureFresh(ctx context.Context, sess *model.Session) (*model.Session, error) {
	now := m.clock.Now()
	if !sess.NeedsRefresh(now, m.cfg.OIDC.RefreshWindow) {
		return sess, nil
	}

	lockOwner, err := model.RandomToken(16)
	if err != nil {
		return nil, fmt.Errorf("generate refresh lock owner: %w", err)
	}

	acquired, err := m.store.AcquireRefreshLock(ctx, sess.ID, lockOwner, m.cfg.Redis.LockRefreshTTL)
	if err != nil {
		if sess.CanServe(now, m.cfg.Session.MinAccessTokenTTL) {
			m.logger.Warn("refresh lock acquisition failed, using existing access token", "session_id", sess.ID, "error", err)
			m.metrics.RefreshTotal.WithLabelValues("lock_error_fallback").Inc()
			return sess, nil
		}
		m.metrics.RefreshTotal.WithLabelValues("lock_error").Inc()
		return nil, err
	}
	if acquired {
		defer func() {
			if releaseErr := m.store.ReleaseRefreshLock(context.Background(), sess.ID, lockOwner); releaseErr != nil {
				m.logger.Warn("failed to release refresh lock", "session_id", sess.ID, "error", releaseErr)
			}
		}()

		latest, err := m.store.GetSession(ctx, sess.ID)
		if err == nil && latest != nil && !latest.NeedsRefresh(now, m.cfg.OIDC.RefreshWindow) {
			return latest, nil
		}

		tokenSet, err := m.oidc.Refresh(ctx, sess.RefreshToken)
		if err != nil {
			if errors.Is(err, oidc.ErrInvalidGrant) {
				if deleteErr := m.store.DeleteSession(ctx, sess.ID); deleteErr != nil {
					m.logger.Warn("failed to delete stale session after invalid_grant", "session_id", sess.ID, "error", deleteErr)
				}
				m.metrics.RefreshTotal.WithLabelValues("invalid_grant").Inc()
				return nil, ErrSessionExpired
			}
			if sess.CanServe(now, m.cfg.Session.MinAccessTokenTTL) {
				m.logger.Warn("refresh failed, using existing access token", "session_id", sess.ID, "error", err)
				m.metrics.RefreshTotal.WithLabelValues("failed_fallback").Inc()
				return sess, nil
			}
			if deleteErr := m.store.DeleteSession(ctx, sess.ID); deleteErr != nil {
				m.logger.Warn("failed to delete stale session after refresh failure", "session_id", sess.ID, "error", deleteErr)
			}
			m.metrics.RefreshTotal.WithLabelValues("failed").Inc()
			return nil, ErrSessionExpired
		}

		updated := *sess
		updated.AccessToken = tokenSet.AccessToken
		updated.AccessTokenExpiry = tokenSet.AccessTokenExpiry
		updated.TokenType = tokenSet.TokenType
		if tokenSet.RefreshToken != "" {
			updated.RefreshToken = tokenSet.RefreshToken
		}
		if tokenSet.RefreshTokenExpiry != nil {
			updated.RefreshTokenExpiry = tokenSet.RefreshTokenExpiry
		}
		if tokenSet.IDToken != "" {
			updated.IDToken = tokenSet.IDToken
		}
		updated.ExpiresAt = m.sessionExpiry(updated.CreatedAt, tokenSet)
		if updated.ExpiresAt.Before(sess.ExpiresAt) {
			updated.ExpiresAt = updated.ExpiresAt
		} else {
			updated.ExpiresAt = sess.ExpiresAt
		}

		if err := m.store.SaveSession(ctx, updated, updated.TTL(now)); err != nil {
			m.metrics.RefreshTotal.WithLabelValues("save_failed").Inc()
			return nil, err
		}
		m.metrics.RefreshTotal.WithLabelValues("success").Inc()
		return &updated, nil
	}

	deadline := now.Add(m.cfg.Redis.LockWaitTimeout)
	for m.clock.Now().Before(deadline) {
		if err := m.clock.Sleep(ctx, m.cfg.Redis.LockPollInterval); err != nil {
			return nil, err
		}
		latest, err := m.store.GetSession(ctx, sess.ID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				m.metrics.RefreshTotal.WithLabelValues("wait_not_found").Inc()
				return nil, ErrSessionExpired
			}
			return nil, err
		}
		if latest.AccessToken != sess.AccessToken || latest.AccessTokenExpiry.After(sess.AccessTokenExpiry) || !latest.NeedsRefresh(m.clock.Now(), m.cfg.OIDC.RefreshWindow) {
			m.metrics.RefreshTotal.WithLabelValues("wait_success").Inc()
			return latest, nil
		}
	}

	if sess.CanServe(m.clock.Now(), m.cfg.Session.MinAccessTokenTTL) {
		m.metrics.RefreshTotal.WithLabelValues("wait_timeout_fallback").Inc()
		return sess, nil
	}
	m.metrics.RefreshTotal.WithLabelValues("wait_timeout").Inc()
	return nil, ErrSessionExpired
}

func (m *Manager) IdentityHeaders(sess *model.Session) SessionIdentity {
	return SessionIdentity{
		AuthorizationValue:     "Bearer " + sess.AccessToken,
		UserHeaderValue:        sess.PreferredUsername,
		EmailHeaderValue:       sess.Email,
		SubjectHeaderValue:     sess.Subject,
		PreferredUsernameValue: sess.PreferredUsername,
		GroupsHeaderValue:      model.GroupsHeader(sess.Groups),
	}
}

func (m *Manager) SessionCookie(sessionID string) *http.Cookie {
	return &http.Cookie{
		Name:     m.cfg.Session.CookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.Session.CookieSecure,
		SameSite: sameSiteMode(m.cfg.Session.CookieSameSite),
		Domain:   m.cfg.Session.CookieDomain,
		Expires:  m.clock.Now().Add(m.cfg.Session.MaxLifetime),
		MaxAge:   int(m.cfg.Session.MaxLifetime.Seconds()),
	}
}

func (m *Manager) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     m.cfg.Session.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.Session.CookieSecure,
		SameSite: sameSiteMode(m.cfg.Session.CookieSameSite),
		Domain:   m.cfg.Session.CookieDomain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	}
}

func (m *Manager) sessionExpiry(createdAt time.Time, tokenSet *oidc.TokenSet) time.Time {
	expiresAt := createdAt.Add(m.cfg.Session.MaxLifetime)
	if tokenSet.RefreshTokenExpiry != nil && tokenSet.RefreshTokenExpiry.Before(expiresAt) {
		expiresAt = *tokenSet.RefreshTokenExpiry
	}
	if tokenSet.RefreshToken == "" && tokenSet.AccessTokenExpiry.Before(expiresAt) {
		expiresAt = tokenSet.AccessTokenExpiry
	}
	return expiresAt
}

func (m *Manager) normalizeReturnPath(returnPath string) string {
	if strings.TrimSpace(returnPath) == "" {
		return "/"
	}
	parsed, err := url.Parse(returnPath)
	if err != nil {
		return "/"
	}

	if parsed.IsAbs() {
		if parsed.Host == "" {
			return "/"
		}
		if !m.hostAllowed(parsed.Host) {
			return "/"
		}
		parsed.Scheme = ""
		parsed.Host = ""
	}

	if !strings.HasPrefix(parsed.Path, "/") {
		return "/"
	}
	if parsed.Path == "/_auth" || strings.HasPrefix(parsed.Path, "/_auth/") {
		return "/"
	}
	if parsed.RawQuery == "" {
		return parsed.Path
	}
	return parsed.Path + "?" + parsed.RawQuery
}

func (m *Manager) validateOrigin(origin string) error {
	parsed, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("parse origin: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return ErrInvalidHost
	}
	if !m.hostAllowed(parsed.Host) {
		return ErrInvalidHost
	}
	return nil
}

func (m *Manager) hostAllowed(host string) bool {
	host = hostOnly(host)
	if len(m.cfg.Session.AllowedHosts) == 0 {
		return true
	}

	for _, allowed := range m.cfg.Session.AllowedHosts {
		allowed = hostOnly(allowed)
		if allowed == host {
			return true
		}
		if strings.HasPrefix(allowed, "*.") && strings.HasSuffix(host, strings.TrimPrefix(allowed, "*")) {
			return true
		}
	}
	return false
}

func hostOnly(hostport string) string {
	hostport = strings.TrimSpace(strings.Split(hostport, ",")[0])
	if strings.HasPrefix(hostport, "[") {
		if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
			return parsedHost
		}
	}
	if strings.Count(hostport, ":") == 1 {
		if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
			return parsedHost
		}
	}
	return hostport
}

func sameSiteMode(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}
