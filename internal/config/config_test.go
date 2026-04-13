package config

import (
	"testing"
	"time"
)

func TestValidate_ValidConfig(t *testing.T) {
	cfg := validTestConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidate_MissingRequired(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantMsg string
	}{
		{
			"missing OIDC_ISSUER_URL",
			func(c *Config) { c.OIDC.IssuerURL = "" },
			"OIDC_ISSUER_URL is required",
		},
		{
			"missing OIDC_CLIENT_ID",
			func(c *Config) { c.OIDC.ClientID = "" },
			"OIDC_CLIENT_ID is required",
		},
		{
			"missing OIDC_CLIENT_SECRET",
			func(c *Config) { c.OIDC.ClientSecret = "" },
			"OIDC_CLIENT_SECRET is required",
		},
		{
			"empty REDIS_ADDRESSES",
			func(c *Config) { c.Redis.Addresses = nil },
			"REDIS_ADDRESSES must not be empty",
		},
		{
			"sentinel without master name",
			func(c *Config) { c.Redis.Mode = "sentinel"; c.Redis.MasterName = "" },
			"REDIS_MASTER_NAME is required for sentinel mode",
		},
		{
			"non-positive SESSION_MAX_LIFETIME",
			func(c *Config) { c.Session.MaxLifetime = 0 },
			"SESSION_MAX_LIFETIME must be positive",
		},
		{
			"__Host- prefix with non-empty domain",
			func(c *Config) { c.Session.CookieName = "__Host-sess"; c.Session.CookieDomain = "example.com" },
			"SESSION_COOKIE_DOMAIN must be empty",
		},
		{
			"zero lock poll interval",
			func(c *Config) { c.Redis.LockPollInterval = 0 },
			"redis refresh lock settings must be positive",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validTestConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantMsg)
			}
			if msg := err.Error(); len(msg) == 0 || !contains(msg, tc.wantMsg) {
				t.Fatalf("Validate() error = %q, want it to contain %q", msg, tc.wantMsg)
			}
		})
	}
}

func TestWarnings_InsecureSkip(t *testing.T) {
	cfg := validTestConfig()
	cfg.Redis.TLSEnabled = true
	cfg.Redis.TLSInsecureSkip = true

	warnings := cfg.Warnings()
	if len(warnings) == 0 {
		t.Fatal("Warnings() = empty, want at least one warning for TLS insecure skip")
	}
}

func TestWarnings_NoWarningsOnCleanConfig(t *testing.T) {
	cfg := validTestConfig()
	if got := cfg.Warnings(); len(got) != 0 {
		t.Fatalf("Warnings() = %v, want empty", got)
	}
}

func TestValidate_PublicOrigin(t *testing.T) {
	t.Run("valid custom port", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.Session.AllowedHosts = []string{"app.example.com"}
		cfg.OIDC.PublicOrigin = "https://app.example.com:8443"

		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v, want nil", err)
		}
	})

	t.Run("host must be allowed", func(t *testing.T) {
		cfg := validTestConfig()
		cfg.Session.AllowedHosts = []string{"app.example.com"}
		cfg.OIDC.PublicOrigin = "https://login.example.com:8443"

		err := cfg.Validate()
		if err == nil {
			t.Fatal("Validate() = nil, want error for disallowed public origin host")
		}
		if msg := err.Error(); !contains(msg, "OIDC_PUBLIC_ORIGIN host must match SESSION_ALLOWED_HOSTS") {
			t.Fatalf("Validate() error = %q, want public origin host mismatch", msg)
		}
	})
}

func TestConfigBuilder_InvalidDuration(t *testing.T) {
	t.Setenv("SERVER_READ_TIMEOUT", "not-a-duration")
	t.Setenv("OIDC_ISSUER_URL", "https://keycloak.example.com/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "test-client")
	t.Setenv("OIDC_CLIENT_SECRET", "test-secret")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("LoadFromEnv() = nil, want error for invalid duration")
	}
}

func TestConfigBuilder_InvalidBool(t *testing.T) {
	t.Setenv("REDIS_TLS_ENABLED", "notabool")
	t.Setenv("OIDC_ISSUER_URL", "https://keycloak.example.com/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "test-client")
	t.Setenv("OIDC_CLIENT_SECRET", "test-secret")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("LoadFromEnv() = nil, want error for invalid bool")
	}
}

func TestConfigBuilder_InvalidInt(t *testing.T) {
	t.Setenv("REDIS_POOL_SIZE", "notanint")
	t.Setenv("OIDC_ISSUER_URL", "https://keycloak.example.com/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "test-client")
	t.Setenv("OIDC_CLIENT_SECRET", "test-secret")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("LoadFromEnv() = nil, want error for invalid int")
	}
}

func TestConfigBuilder_InvalidFloat(t *testing.T) {
	t.Setenv("RATE_LIMIT_RPS", "notafloat")
	t.Setenv("OIDC_ISSUER_URL", "https://keycloak.example.com/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "test-client")
	t.Setenv("OIDC_CLIENT_SECRET", "test-secret")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("LoadFromEnv() = nil, want error for invalid float")
	}
}

func TestEnvCSV(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		fallback []string
		want     []string
	}{
		{"empty uses fallback", "", []string{"a", "b"}, []string{"a", "b"}},
		{"nil fallback returns nil", "", nil, nil},
		{"csv parsed", "a,b,c", nil, []string{"a", "b", "c"}},
		{"csv trims spaces", " a , b , c ", nil, []string{"a", "b", "c"}},
		{"csv skips empty parts", "a,,b", nil, []string{"a", "b"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("__TEST_CSV__", tc.envValue)
			got := envCSV("__TEST_CSV__", tc.fallback)
			if len(got) != len(tc.want) {
				t.Fatalf("envCSV() = %v, want %v", got, tc.want)
			}
			for i, v := range got {
				if v != tc.want[i] {
					t.Fatalf("envCSV()[%d] = %q, want %q", i, v, tc.want[i])
				}
			}
		})
	}
}

func TestLoadFromEnv_NormalizesPublicOrigin(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "https://keycloak.example.com/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "test-client")
	t.Setenv("OIDC_CLIENT_SECRET", "test-secret")
	t.Setenv("OIDC_PUBLIC_ORIGIN", "https://app.example.com:443/")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv() error = %v", err)
	}
	if cfg.OIDC.PublicOrigin != "https://app.example.com" {
		t.Fatalf("LoadFromEnv() public origin = %q, want https://app.example.com", cfg.OIDC.PublicOrigin)
	}
}

// helpers

func validTestConfig() Config {
	return Config{
		OIDC: OIDCConfig{
			IssuerURL:    "https://keycloak.example.com/realms/test",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
		},
		Redis: RedisConfig{
			Addresses:        []string{"127.0.0.1:6379"},
			Mode:             "standalone",
			MasterName:       "mymaster",
			LockRefreshTTL:   5 * time.Second,
			LockWaitTimeout:  1 * time.Second,
			LockPollInterval: 50 * time.Millisecond,
		},
		Session: SessionConfig{
			CookieName:  "__Host-oidc_session",
			MaxLifetime: 12 * time.Hour,
		},
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
