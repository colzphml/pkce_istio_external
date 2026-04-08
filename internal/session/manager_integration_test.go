package session

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/colzphml/pkce_istio_external/internal/model"
	"github.com/colzphml/pkce_istio_external/internal/oidc"
	"github.com/colzphml/pkce_istio_external/internal/store"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
	"github.com/colzphml/pkce_istio_external/internal/testutil"
)

func TestLoginCallbackLogoutFlowWithRedisStore(t *testing.T) {
	now := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	mr := miniredis.RunT(t)

	cfg := testutil.BaseConfig(now)
	cfg.Redis.Addresses = []string{mr.Addr()}

	redisStore, err := store.NewRedisStore(cfg.Redis)
	if err != nil {
		t.Fatalf("NewRedisStore() error = %v", err)
	}

	fakeOIDC := &testutil.FakeOIDCClient{
		ExchangeToken: &oidc.TokenSet{
			AccessToken:       "access-token",
			RefreshToken:      "refresh-token",
			IDToken:           "id-token",
			TokenType:         "Bearer",
			AccessTokenExpiry: now.Add(30 * time.Minute),
		},
		ExchangeIdentity: &oidc.Identity{
			Subject:           "user-1",
			Email:             "user@example.com",
			PreferredUsername: "user",
			Nonce:             "will-be-replaced",
			KCSessionID:       "kc-session-1",
			Issuer:            cfg.OIDC.IssuerURL,
			Audience:          []string{cfg.OIDC.ClientID},
		},
		LogoutURL: "https://keycloak.example.com/logout",
	}
	clk := testutil.NewFixedClock(now)
	manager := NewManager(cfg, redisStore, fakeOIDC, testutil.DiscardLogger(), clk, telemetry.New())

	loginURL, err := manager.BeginLogin(context.Background(), "https://app.example.com", "/orders?id=42")
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	parsedLoginURL, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("Parse(loginURL) error = %v", err)
	}
	state := parsedLoginURL.Query().Get("state")
	if state == "" {
		t.Fatalf("state missing in login URL")
	}
	fakeOIDC.ExchangeIdentity.Nonce = fakeOIDC.LastAuthNonce

	sess, returnPath, err := manager.CompleteLogin(context.Background(), "https://app.example.com", state, "auth-code")
	if err != nil {
		t.Fatalf("CompleteLogin() error = %v", err)
	}
	if returnPath != "/orders?id=42" {
		t.Fatalf("returnPath = %q, want /orders?id=42", returnPath)
	}

	persisted, err := redisStore.GetSession(context.Background(), sess.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if persisted.AccessToken != "access-token" {
		t.Fatalf("access token = %q, want access-token", persisted.AccessToken)
	}

	redirectURL, err := manager.Logout(context.Background(), "https://app.example.com", sess.ID)
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if redirectURL != "https://keycloak.example.com/logout" {
		t.Fatalf("Logout() redirect = %q", redirectURL)
	}
	if _, err := redisStore.GetSession(context.Background(), sess.ID); err == nil {
		t.Fatalf("session still exists after logout")
	}
}

func TestBackchannelLogoutDeletesAllSessionsForKCSessionID(t *testing.T) {
	now := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	mr := miniredis.RunT(t)

	cfg := testutil.BaseConfig(now)
	cfg.Redis.Addresses = []string{mr.Addr()}

	redisStore, err := store.NewRedisStore(cfg.Redis)
	if err != nil {
		t.Fatalf("NewRedisStore() error = %v", err)
	}

	fakeOIDC := &testutil.FakeOIDCClient{
		LogoutToken: &oidc.LogoutToken{KCSessionID: "kc-session-1"},
	}
	clk := testutil.NewFixedClock(now)
	manager := NewManager(cfg, redisStore, fakeOIDC, testutil.DiscardLogger(), clk, telemetry.New())

	sessions := []model.Session{
		{ID: "session-1", KCSessionID: "kc-session-1", AccessToken: "a", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		{ID: "session-2", KCSessionID: "kc-session-1", AccessToken: "b", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
	for _, sess := range sessions {
		if err := redisStore.SaveSession(context.Background(), sess, sess.TTL(now)); err != nil {
			t.Fatalf("SaveSession() error = %v", err)
		}
	}

	deleted, err := manager.BackchannelLogout(context.Background(), "logout-token")
	if err != nil {
		t.Fatalf("BackchannelLogout() error = %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}

	for _, id := range []string{"session-1", "session-2"} {
		if _, err := redisStore.GetSession(context.Background(), id); err == nil {
			t.Fatalf("%s still exists after backchannel logout", id)
		}
	}
}
