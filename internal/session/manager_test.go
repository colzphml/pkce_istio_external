package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/colzphml/pkce_istio_external/internal/model"
	"github.com/colzphml/pkce_istio_external/internal/oidc"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
	"github.com/colzphml/pkce_istio_external/internal/testutil"
)

func TestEnsureFreshRefreshesAndPersistsSession(t *testing.T) {
	now := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	cfg := testutil.BaseConfig(now)
	memStore := testutil.NewMemoryStore()
	fakeOIDC := &testutil.FakeOIDCClient{
		RefreshToken: &oidc.TokenSet{
			AccessToken:       "new-access-token",
			RefreshToken:      "new-refresh-token",
			IDToken:           "new-id-token",
			TokenType:         "Bearer",
			AccessTokenExpiry: now.Add(30 * time.Minute),
		},
	}
	clk := testutil.NewFixedClock(now)
	manager := NewManager(cfg, memStore, fakeOIDC, testutil.DiscardLogger(), clk, telemetry.New())

	original := model.Session{
		ID:                "session-1",
		AccessToken:       "old-access-token",
		RefreshToken:      "refresh-token",
		IDToken:           "id-token",
		TokenType:         "Bearer",
		AccessTokenExpiry: now.Add(30 * time.Second),
		CreatedAt:         now,
		ExpiresAt:         now.Add(2 * time.Hour),
	}
	if err := memStore.SaveSession(context.Background(), original, original.TTL(now)); err != nil {
		t.Fatalf("save session: %v", err)
	}

	got, err := manager.EnsureFresh(context.Background(), &original)
	if err != nil {
		t.Fatalf("EnsureFresh() error = %v", err)
	}
	if got.AccessToken != "new-access-token" {
		t.Fatalf("EnsureFresh() access token = %q, want new token", got.AccessToken)
	}
	if fakeOIDC.RefreshCalls != 1 {
		t.Fatalf("Refresh() calls = %d, want 1", fakeOIDC.RefreshCalls)
	}

	persisted, err := memStore.GetSession(context.Background(), original.ID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}
	if persisted.AccessToken != "new-access-token" {
		t.Fatalf("persisted access token = %q, want new token", persisted.AccessToken)
	}
}

func TestEnsureFreshInvalidGrantDeletesSession(t *testing.T) {
	now := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	cfg := testutil.BaseConfig(now)
	memStore := testutil.NewMemoryStore()
	fakeOIDC := &testutil.FakeOIDCClient{
		RefreshErr: errors.Join(errors.New("revoked"), oidc.ErrInvalidGrant),
	}
	clk := testutil.NewFixedClock(now)
	manager := NewManager(cfg, memStore, fakeOIDC, testutil.DiscardLogger(), clk, telemetry.New())

	original := model.Session{
		ID:                "session-1",
		AccessToken:       "old-access-token",
		RefreshToken:      "refresh-token",
		AccessTokenExpiry: now.Add(5 * time.Second),
		CreatedAt:         now,
		ExpiresAt:         now.Add(2 * time.Hour),
	}
	if err := memStore.SaveSession(context.Background(), original, original.TTL(now)); err != nil {
		t.Fatalf("save session: %v", err)
	}

	_, err := manager.EnsureFresh(context.Background(), &original)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("EnsureFresh() error = %v, want ErrSessionExpired", err)
	}
	if _, err := memStore.GetSession(context.Background(), original.ID); err == nil {
		t.Fatalf("session still exists after invalid_grant")
	}
}

func TestLogoutDeletesSessionsByKCSessionID(t *testing.T) {
	now := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	cfg := testutil.BaseConfig(now)
	memStore := testutil.NewMemoryStore()
	fakeOIDC := &testutil.FakeOIDCClient{
		LogoutURL: "https://keycloak.example.com/logout",
	}
	clk := testutil.NewFixedClock(now)
	manager := NewManager(cfg, memStore, fakeOIDC, testutil.DiscardLogger(), clk, telemetry.New())

	sessions := []model.Session{
		{ID: "session-1", KCSessionID: "kc-1", IDToken: "id-1", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
		{ID: "session-2", KCSessionID: "kc-1", IDToken: "id-2", CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	}
	for _, sess := range sessions {
		if err := memStore.SaveSession(context.Background(), sess, sess.TTL(now)); err != nil {
			t.Fatalf("save session: %v", err)
		}
	}

	redirectURL, err := manager.Logout(context.Background(), "https://app.example.com", "session-1")
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if redirectURL != "https://keycloak.example.com/logout" {
		t.Fatalf("Logout() redirect = %q", redirectURL)
	}
	if _, err := memStore.GetSession(context.Background(), "session-1"); err == nil {
		t.Fatalf("session-1 still exists after logout")
	}
	if _, err := memStore.GetSession(context.Background(), "session-2"); err == nil {
		t.Fatalf("session-2 still exists after logout")
	}
}
