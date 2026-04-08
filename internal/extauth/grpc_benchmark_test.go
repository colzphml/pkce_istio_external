package extauth

import (
	"context"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/colzphml/pkce_istio_external/internal/model"
	"github.com/colzphml/pkce_istio_external/internal/session"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
	"github.com/colzphml/pkce_istio_external/internal/testutil"
)

func BenchmarkCheckValidSession(b *testing.B) {
	now := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	cfg := testutil.BaseConfig(now)
	memStore := testutil.NewMemoryStore()
	clk := testutil.NewFixedClock(now)
	fakeOIDC := &testutil.FakeOIDCClient{}
	manager := session.NewManager(cfg, memStore, fakeOIDC, testutil.DiscardLogger(), clk, telemetry.New())

	validSession := model.Session{
		ID:                "session-1",
		Subject:           "user-1",
		Email:             "user@example.com",
		PreferredUsername: "user",
		Groups:            []string{"dev", "ops"},
		AccessToken:       "access-token",
		RefreshToken:      "refresh-token",
		TokenType:         "Bearer",
		AccessTokenExpiry: now.Add(30 * time.Minute),
		CreatedAt:         now,
		ExpiresAt:         now.Add(12 * time.Hour),
	}
	if err := memStore.SaveSession(context.Background(), validSession, validSession.TTL(now)); err != nil {
		b.Fatalf("SaveSession() error = %v", err)
	}

	server := NewServer(manager, cfg, testutil.DiscardLogger(), telemetry.New())
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Host: "app.example.com",
					Path: "/dashboard",
					Headers: map[string]string{
						":path":  "/dashboard?view=summary",
						"cookie": "__Host-oidc_session=session-1",
						"host":   "app.example.com",
					},
				},
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := server.Check(context.Background(), req); err != nil {
			b.Fatalf("Check() error = %v", err)
		}
	}
}
