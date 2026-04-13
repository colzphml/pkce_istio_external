package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/colzphml/pkce_istio_external/internal/config"
	"github.com/colzphml/pkce_istio_external/internal/model"
	"github.com/colzphml/pkce_istio_external/internal/oidc"
	"github.com/colzphml/pkce_istio_external/internal/session"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
	"github.com/colzphml/pkce_istio_external/internal/testutil"
)

// buildServer is a test helper that creates an httpserver.Server with
// in-memory fakes and returns its underlying http.Handler for testing.
func buildServer(t *testing.T, cfg config.Config, fakeOIDC *testutil.FakeOIDCClient, memStore *testutil.MemoryStore) http.Handler {
	t.Helper()
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	clk := testutil.NewFixedClock(now)
	metrics := telemetry.New()
	mgr := session.NewManager(cfg, memStore, fakeOIDC, testutil.DiscardLogger(), clk, metrics)
	srv := New(cfg.Server.HTTPAddr, mgr, cfg, testutil.DiscardLogger(), metrics, func() error { return nil })
	return srv.HTTPServer().Handler
}

func baseTestConfig() config.Config {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	cfg := testutil.BaseConfig(now)
	cfg.Server.RateLimitRPS = 0 // disable rate limiting in tests
	return cfg
}

// ---- originFromRequest ----

func TestOriginFromRequest_AllowedHost(t *testing.T) {
	cfg := baseTestConfig()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")

	got, err := originFromRequest(r, cfg)
	if err != nil {
		t.Fatalf("originFromRequest() error = %v", err)
	}
	if got != "https://app.example.com" {
		t.Fatalf("originFromRequest() = %q, want https://app.example.com", got)
	}
}

func TestOriginFromRequest_DisallowedHost(t *testing.T) {
	cfg := baseTestConfig()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "evil.example.com")

	_, err := originFromRequest(r, cfg)
	if err == nil {
		t.Fatal("originFromRequest() = nil, want error for disallowed host")
	}
}

func TestOriginFromRequest_AllowedWildcard(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Session.AllowedHosts = []string{"*.example.com"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "sub.example.com")

	_, err := originFromRequest(r, cfg)
	if err != nil {
		t.Fatalf("originFromRequest() wildcard error = %v", err)
	}
}

func TestOriginFromRequest_PreservesNonDefaultPort(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Session.AllowedHosts = []string{"localhost"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Host", "localhost:8080")

	got, err := originFromRequest(r, cfg)
	if err != nil {
		t.Fatalf("originFromRequest() error = %v", err)
	}
	if got != "http://localhost:8080" {
		t.Fatalf("originFromRequest() = %q, want http://localhost:8080", got)
	}
}

func TestOriginFromRequest_UsesForwardedPortWhenHostOmitsIt(t *testing.T) {
	cfg := baseTestConfig()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")
	r.Header.Set("X-Forwarded-Port", "8443")

	got, err := originFromRequest(r, cfg)
	if err != nil {
		t.Fatalf("originFromRequest() error = %v", err)
	}
	if got != "https://app.example.com:8443" {
		t.Fatalf("originFromRequest() = %q, want https://app.example.com:8443", got)
	}
}

func TestOriginFromRequest_PublicOriginOverride(t *testing.T) {
	cfg := baseTestConfig()
	cfg.OIDC.PublicOrigin = "https://login.example.com:8443/"
	cfg.Session.AllowedHosts = []string{"app.example.com", "login.example.com"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "app.example.com")

	got, err := originFromRequest(r, cfg)
	if err != nil {
		t.Fatalf("originFromRequest() error = %v", err)
	}
	if got != "https://login.example.com:8443" {
		t.Fatalf("originFromRequest() = %q, want https://login.example.com:8443", got)
	}
}

// ---- normalizeReturnPath ----

func TestNormalizeReturnPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "/"},
		{"/foo", "/foo"},
		{"/foo?bar=1", "/foo?bar=1"},
		{"/_auth/callback", "/"},
		{"/_auth", "/"},
		{"/_auth/", "/"},
		{"relative", "/"},
		{"https://evil.com/steal", "/"},
	}

	for _, tc := range tests {
		got := normalizeReturnPath(tc.input)
		if got != tc.want {
			t.Errorf("normalizeReturnPath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---- handleLogin ----

func TestHandleLogin_NoSession_RedirectsToOIDC(t *testing.T) {
	cfg := baseTestConfig()
	handler := buildServer(t, cfg, &testutil.FakeOIDCClient{}, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/_auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("handleLogin() status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "keycloak.example.com") {
		t.Fatalf("handleLogin() location = %q, does not contain keycloak.example.com", loc)
	}
}

func TestHandleLogin_DisallowedHost_Returns403(t *testing.T) {
	cfg := baseTestConfig()
	handler := buildServer(t, cfg, &testutil.FakeOIDCClient{}, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/_auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "evil.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("handleLogin() status = %d, want 403 for disallowed host", rec.Code)
	}
}

func TestHandleLogin_PreservesCustomPortInRedirectURI(t *testing.T) {
	cfg := baseTestConfig()
	cfg.Session.AllowedHosts = []string{"localhost"}
	fakeOIDC := &testutil.FakeOIDCClient{}
	handler := buildServer(t, cfg, fakeOIDC, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/_auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "localhost:8080")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("handleLogin() status = %d, want 302", rec.Code)
	}
	if fakeOIDC.LastAuthRedirectURL != "http://localhost:8080/_auth/callback" {
		t.Fatalf("handleLogin() redirect_uri = %q, want http://localhost:8080/_auth/callback", fakeOIDC.LastAuthRedirectURL)
	}
}

func TestHandleLogin_UsesConfiguredPublicOriginInRedirectURI(t *testing.T) {
	cfg := baseTestConfig()
	cfg.OIDC.PublicOrigin = "https://login.example.com:8443"
	cfg.Session.AllowedHosts = []string{"app.example.com", "login.example.com"}
	fakeOIDC := &testutil.FakeOIDCClient{}
	handler := buildServer(t, cfg, fakeOIDC, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/_auth/login", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("handleLogin() status = %d, want 302", rec.Code)
	}
	if fakeOIDC.LastAuthRedirectURL != "https://login.example.com:8443/_auth/callback" {
		t.Fatalf("handleLogin() redirect_uri = %q, want https://login.example.com:8443/_auth/callback", fakeOIDC.LastAuthRedirectURL)
	}
}

// ---- handleCallback ----

func TestHandleCallback_OIDCError_Returns401(t *testing.T) {
	cfg := baseTestConfig()
	handler := buildServer(t, cfg, &testutil.FakeOIDCClient{}, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/_auth/callback?error=access_denied", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("handleCallback() status = %d, want 401", rec.Code)
	}
}

func TestHandleCallback_MissingState_Returns400(t *testing.T) {
	cfg := baseTestConfig()
	handler := buildServer(t, cfg, &testutil.FakeOIDCClient{}, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/_auth/callback?code=abc123", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// state not found → ErrStateNotFound → 401
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("handleCallback() missing state status = %d, want 401", rec.Code)
	}
}

func TestHandleCallback_Success_SetsCookieAndRedirects(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	cfg := baseTestConfig()
	memStore := testutil.NewMemoryStore()
	fakeOIDC := &testutil.FakeOIDCClient{
		ExchangeToken: &oidc.TokenSet{
			AccessToken:       "access",
			RefreshToken:      "refresh",
			IDToken:           "id",
			TokenType:         "Bearer",
			AccessTokenExpiry: now.Add(30 * time.Minute),
		},
		ExchangeIdentity: &oidc.Identity{
			Subject: "user-1",
			Nonce:   "testnonce",
		},
	}

	clk := testutil.NewFixedClock(now)
	metrics := telemetry.New()
	mgr := session.NewManager(cfg, memStore, fakeOIDC, testutil.DiscardLogger(), clk, metrics)

	// Pre-populate a login state with a known nonce so CompleteLogin passes.
	loginState := model.LoginState{
		State:        "teststate",
		Nonce:        "testnonce",
		CodeVerifier: "verifier",
		ReturnPath:   "/dashboard",
		CreatedAt:    now,
	}
	_ = memStore.SaveLoginState(nil, loginState, 10*time.Minute) //nolint:staticcheck

	srv := New(cfg.Server.HTTPAddr, mgr, cfg, testutil.DiscardLogger(), metrics, func() error { return nil })
	handler := srv.HTTPServer().Handler

	req := httptest.NewRequest(http.MethodGet, "/_auth/callback?state=teststate&code=authcode", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("handleCallback() success status = %d, want 302", rec.Code)
	}
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "__Host-") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("handleCallback() success: no __Host- session cookie set")
	}
}

// ---- handleLogout ----

func TestHandleLogout_NoSession_Redirects(t *testing.T) {
	cfg := baseTestConfig()
	handler := buildServer(t, cfg, &testutil.FakeOIDCClient{}, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodGet, "/_auth/logout", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("handleLogout() status = %d, want 302", rec.Code)
	}
}

func TestHandleLogout_POST_CrossOrigin_Returns403(t *testing.T) {
	cfg := baseTestConfig()
	handler := buildServer(t, cfg, &testutil.FakeOIDCClient{}, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodPost, "/_auth/logout", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("handleLogout() cross-origin POST status = %d, want 403", rec.Code)
	}
}

func TestHandleLogout_POST_SameOrigin_Redirects(t *testing.T) {
	cfg := baseTestConfig()
	handler := buildServer(t, cfg, &testutil.FakeOIDCClient{}, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodPost, "/_auth/logout", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "app.example.com")
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("handleLogout() same-origin POST status = %d, want 302", rec.Code)
	}
}

// ---- handleBackchannelLogout ----

func TestHandleBackchannelLogout_MissingToken_Returns400(t *testing.T) {
	cfg := baseTestConfig()
	handler := buildServer(t, cfg, &testutil.FakeOIDCClient{}, testutil.NewMemoryStore())

	req := httptest.NewRequest(http.MethodPost, "/_auth/backchannel-logout", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("handleBackchannelLogout() missing token status = %d, want 400", rec.Code)
	}
}

func TestHandleBackchannelLogout_InvalidToken_Returns401(t *testing.T) {
	cfg := baseTestConfig()
	fakeOIDC := &testutil.FakeOIDCClient{
		VerifyLogoutErr: errFakeVerify,
	}
	handler := buildServer(t, cfg, fakeOIDC, testutil.NewMemoryStore())

	body := strings.NewReader("logout_token=invalid-token")
	req := httptest.NewRequest(http.MethodPost, "/_auth/backchannel-logout", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("handleBackchannelLogout() invalid token status = %d, want 401", rec.Code)
	}
}

func TestHandleBackchannelLogout_ValidToken_Returns200(t *testing.T) {
	cfg := baseTestConfig()
	fakeOIDC := &testutil.FakeOIDCClient{
		LogoutToken: &oidc.LogoutToken{Subject: "user-1", KCSessionID: "kc-sess-1"},
	}
	handler := buildServer(t, cfg, fakeOIDC, testutil.NewMemoryStore())

	body := strings.NewReader("logout_token=valid-token")
	req := httptest.NewRequest(http.MethodPost, "/_auth/backchannel-logout", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handleBackchannelLogout() valid token status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// sentinel error for testing
var errFakeVerify = &fakeVerifyError{}

type fakeVerifyError struct{}

func (e *fakeVerifyError) Error() string { return "fake verify error" }
