package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/colzphml/pkce_istio_external/internal/netutil"
)

type Config struct {
	Log     LogConfig
	Server  ServerConfig
	OIDC    OIDCConfig
	Redis   RedisConfig
	Session SessionConfig
	Headers HeaderConfig
}

type LogConfig struct {
	Level string
}

type ServerConfig struct {
	HTTPAddr        string
	GRPCAddr        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	// RateLimitRPS controls the per-IP request rate for /_auth/* endpoints.
	// Set to 0 to disable rate limiting. Default: 10.
	RateLimitRPS float64
	// RateLimitBurst controls the burst size for the per-IP rate limiter. Default: 20.
	RateLimitBurst int
}

type OIDCConfig struct {
	IssuerURL            string
	ClientID             string
	ClientSecret         string
	PublicOrigin         string
	Scopes               []string
	CallbackPath         string
	LogoutPath           string
	PostLogoutPath       string
	BackchannelPath      string
	LoginPath            string
	LoginStateTTL        time.Duration
	RefreshWindow        time.Duration
	HTTPTimeout          time.Duration
	ClockSkew            time.Duration
	AccessTokenAudiences []string
	// CircuitBreakerMaxFailures is the number of consecutive failures before the
	// circuit breaker opens. Set to 0 to disable. Default: 5.
	CircuitBreakerMaxFailures int
	// CircuitBreakerTimeout is how long the circuit stays open before attempting
	// half-open. Default: 30s.
	CircuitBreakerTimeout time.Duration
}

type RedisConfig struct {
	Mode             string
	Addresses        []string
	MasterName       string
	Username         string
	Password         string
	SentinelUsername string
	SentinelPassword string
	DB               int
	KeyPrefix        string
	DialTimeout      time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	PoolSize         int
	MinIdleConns     int
	TLSEnabled       bool
	TLSServerName    string
	TLSInsecureSkip  bool
	TLSCAFile        string
	TLSCertFile      string
	TLSKeyFile       string
	LockRefreshTTL   time.Duration
	LockWaitTimeout  time.Duration
	LockPollInterval time.Duration
}

type SessionConfig struct {
	CookieName        string
	CookieDomain      string
	CookieSecure      bool
	CookieSameSite    string
	MaxLifetime       time.Duration
	MinAccessTokenTTL time.Duration
	AllowedHosts      []string
}

type HeaderConfig struct {
	AuthorizationHeader     string
	UserHeader              string
	EmailHeader             string
	SubjectHeader           string
	PreferredUsernameHeader string
	GroupsHeader            string
}

// configBuilder accumulates errors from env parsing so that all problems are
// reported at once instead of panicking on the first bad value.
type configBuilder struct {
	errs []error
}

func (b *configBuilder) duration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		b.errs = append(b.errs, fmt.Errorf("invalid duration for %s=%q: %w", key, value, err))
		return fallback
	}
	return parsed
}

func (b *configBuilder) boolean(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		b.errs = append(b.errs, fmt.Errorf("invalid bool for %s=%q: %w", key, value, err))
		return fallback
	}
	return parsed
}

func (b *configBuilder) integer(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		b.errs = append(b.errs, fmt.Errorf("invalid int for %s=%q: %w", key, value, err))
		return fallback
	}
	return parsed
}

func (b *configBuilder) float64Val(key string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		b.errs = append(b.errs, fmt.Errorf("invalid float for %s=%q: %w", key, value, err))
		return fallback
	}
	return parsed
}

func (b *configBuilder) err() error {
	return errors.Join(b.errs...)
}

func LoadFromEnv() (Config, error) {
	var b configBuilder

	cfg := Config{
		Log: LogConfig{
			Level: envString("LOG_LEVEL", "info"),
		},
		Server: ServerConfig{
			HTTPAddr:        envString("SERVER_HTTP_ADDR", ":8080"),
			GRPCAddr:        envString("SERVER_GRPC_ADDR", ":9090"),
			ReadTimeout:     b.duration("SERVER_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:    b.duration("SERVER_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:     b.duration("SERVER_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: b.duration("SERVER_SHUTDOWN_TIMEOUT", 20*time.Second),
			RateLimitRPS:    b.float64Val("RATE_LIMIT_RPS", 10),
			RateLimitBurst:  b.integer("RATE_LIMIT_BURST", 20),
		},
		OIDC: OIDCConfig{
			IssuerURL:                 envRequired("OIDC_ISSUER_URL"),
			ClientID:                  envRequired("OIDC_CLIENT_ID"),
			ClientSecret:              envRequired("OIDC_CLIENT_SECRET"),
			PublicOrigin:              envString("OIDC_PUBLIC_ORIGIN", ""),
			Scopes:                    envCSV("OIDC_SCOPES", []string{"openid", "profile", "email", "offline_access"}),
			CallbackPath:              envString("OIDC_CALLBACK_PATH", "/_auth/callback"),
			LogoutPath:                envString("OIDC_LOGOUT_PATH", "/_auth/logout"),
			PostLogoutPath:            envString("OIDC_POST_LOGOUT_PATH", "/"),
			BackchannelPath:           envString("OIDC_BACKCHANNEL_LOGOUT_PATH", "/_auth/backchannel-logout"),
			LoginPath:                 envString("OIDC_LOGIN_PATH", "/_auth/login"),
			LoginStateTTL:             b.duration("OIDC_LOGIN_STATE_TTL", 10*time.Minute),
			RefreshWindow:             b.duration("OIDC_REFRESH_WINDOW", 2*time.Minute),
			HTTPTimeout:               b.duration("OIDC_HTTP_TIMEOUT", 5*time.Second),
			ClockSkew:                 b.duration("OIDC_CLOCK_SKEW", 30*time.Second),
			AccessTokenAudiences:      envCSV("OIDC_ACCESS_TOKEN_AUDIENCES", nil),
			CircuitBreakerMaxFailures: b.integer("OIDC_CB_MAX_FAILURES", 5),
			CircuitBreakerTimeout:     b.duration("OIDC_CB_TIMEOUT", 30*time.Second),
		},
		Redis: RedisConfig{
			Mode:             envString("REDIS_MODE", "standalone"),
			Addresses:        envCSV("REDIS_ADDRESSES", []string{"127.0.0.1:6379"}),
			MasterName:       envString("REDIS_MASTER_NAME", "mymaster"),
			Username:         envString("REDIS_USERNAME", ""),
			Password:         envString("REDIS_PASSWORD", ""),
			SentinelUsername: envString("REDIS_SENTINEL_USERNAME", ""),
			SentinelPassword: envString("REDIS_SENTINEL_PASSWORD", ""),
			DB:               b.integer("REDIS_DB", 0),
			KeyPrefix:        envString("REDIS_KEY_PREFIX", "oidc:"),
			DialTimeout:      b.duration("REDIS_DIAL_TIMEOUT", 2*time.Second),
			ReadTimeout:      b.duration("REDIS_READ_TIMEOUT", 2*time.Second),
			WriteTimeout:     b.duration("REDIS_WRITE_TIMEOUT", 2*time.Second),
			PoolSize:         b.integer("REDIS_POOL_SIZE", 64),
			MinIdleConns:     b.integer("REDIS_MIN_IDLE_CONNS", 16),
			TLSEnabled:       b.boolean("REDIS_TLS_ENABLED", false),
			TLSServerName:    envString("REDIS_TLS_SERVER_NAME", ""),
			TLSInsecureSkip:  b.boolean("REDIS_TLS_INSECURE_SKIP_VERIFY", false),
			TLSCAFile:        envString("REDIS_TLS_CA_FILE", ""),
			TLSCertFile:      envString("REDIS_TLS_CERT_FILE", ""),
			TLSKeyFile:       envString("REDIS_TLS_KEY_FILE", ""),
			LockRefreshTTL:   b.duration("REDIS_REFRESH_LOCK_TTL", 15*time.Second),
			LockWaitTimeout:  b.duration("REDIS_REFRESH_LOCK_WAIT_TIMEOUT", 2*time.Second),
			LockPollInterval: b.duration("REDIS_REFRESH_LOCK_POLL_INTERVAL", 50*time.Millisecond),
		},
		Session: SessionConfig{
			CookieName:        envString("SESSION_COOKIE_NAME", "__Host-oidc_session"),
			CookieDomain:      envString("SESSION_COOKIE_DOMAIN", ""),
			CookieSecure:      b.boolean("SESSION_COOKIE_SECURE", true),
			CookieSameSite:    envString("SESSION_COOKIE_SAMESITE", "Lax"),
			MaxLifetime:       b.duration("SESSION_MAX_LIFETIME", 12*time.Hour),
			MinAccessTokenTTL: b.duration("SESSION_MIN_ACCESS_TOKEN_TTL", 10*time.Second),
			AllowedHosts:      envCSV("SESSION_ALLOWED_HOSTS", nil),
		},
		Headers: HeaderConfig{
			AuthorizationHeader:     envString("AUTHZ_AUTHORIZATION_HEADER", "authorization"),
			UserHeader:              envString("AUTHZ_USER_HEADER", "x-auth-request-user"),
			EmailHeader:             envString("AUTHZ_EMAIL_HEADER", "x-auth-request-email"),
			SubjectHeader:           envString("AUTHZ_SUBJECT_HEADER", "x-auth-request-sub"),
			PreferredUsernameHeader: envString("AUTHZ_PREFERRED_USERNAME_HEADER", "x-auth-request-preferred-username"),
			GroupsHeader:            envString("AUTHZ_GROUPS_HEADER", "x-auth-request-groups"),
		},
	}

	if parseErr := b.err(); parseErr != nil {
		return Config{}, fmt.Errorf("config parse error: %w", parseErr)
	}

	if len(cfg.OIDC.AccessTokenAudiences) == 0 && cfg.OIDC.ClientID != "" {
		cfg.OIDC.AccessTokenAudiences = []string{cfg.OIDC.ClientID}
	}
	if strings.TrimSpace(cfg.OIDC.PublicOrigin) != "" {
		normalized, err := netutil.NormalizeOrigin(cfg.OIDC.PublicOrigin)
		if err != nil {
			return Config{}, fmt.Errorf("invalid OIDC_PUBLIC_ORIGIN=%q: %w", cfg.OIDC.PublicOrigin, err)
		}
		cfg.OIDC.PublicOrigin = normalized
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error

	if c.OIDC.IssuerURL == "" {
		errs = append(errs, errors.New("OIDC_ISSUER_URL is required"))
	}
	if c.OIDC.ClientID == "" {
		errs = append(errs, errors.New("OIDC_CLIENT_ID is required"))
	}
	if c.OIDC.ClientSecret == "" {
		errs = append(errs, errors.New("OIDC_CLIENT_SECRET is required"))
	}
	if strings.TrimSpace(c.OIDC.PublicOrigin) != "" {
		normalized, err := netutil.NormalizeOrigin(c.OIDC.PublicOrigin)
		if err != nil {
			errs = append(errs, fmt.Errorf("OIDC_PUBLIC_ORIGIN is invalid: %w", err))
		} else if len(c.Session.AllowedHosts) > 0 && !configHostAllowed(normalized, c.Session.AllowedHosts) {
			errs = append(errs, errors.New("OIDC_PUBLIC_ORIGIN host must match SESSION_ALLOWED_HOSTS"))
		}
	}
	if len(c.Redis.Addresses) == 0 {
		errs = append(errs, errors.New("REDIS_ADDRESSES must not be empty"))
	}
	if strings.HasPrefix(c.Session.CookieName, "__Host-") && c.Session.CookieDomain != "" {
		errs = append(errs, errors.New("SESSION_COOKIE_DOMAIN must be empty when SESSION_COOKIE_NAME uses __Host- prefix"))
	}
	if c.Redis.Mode == "sentinel" && c.Redis.MasterName == "" {
		errs = append(errs, errors.New("REDIS_MASTER_NAME is required for sentinel mode"))
	}
	if c.Session.MaxLifetime <= 0 {
		errs = append(errs, errors.New("SESSION_MAX_LIFETIME must be positive"))
	}
	if c.Redis.LockPollInterval <= 0 || c.Redis.LockWaitTimeout <= 0 || c.Redis.LockRefreshTTL <= 0 {
		errs = append(errs, errors.New("redis refresh lock settings must be positive"))
	}

	return errors.Join(errs...)
}

// Warnings returns a list of non-fatal configuration warnings that should be
// logged at startup.
func (c Config) Warnings() []string {
	var warnings []string
	if c.Redis.TLSEnabled && c.Redis.TLSInsecureSkip {
		warnings = append(warnings, "REDIS_TLS_INSECURE_SKIP_VERIFY is enabled: TLS certificate verification is disabled; do not use in production")
	}
	return warnings
}

func configHostAllowed(origin string, allowedHosts []string) bool {
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := netutil.HostOnly(parsed.Host)
	if len(allowedHosts) == 0 {
		return true
	}
	for _, allowed := range allowedHosts {
		allowed = netutil.HostOnly(allowed)
		if allowed == host {
			return true
		}
		if strings.HasPrefix(allowed, "*.") && strings.HasSuffix(host, strings.TrimPrefix(allowed, "*")) {
			return true
		}
	}
	return false
}

func (c RedisConfig) TLSConfig() (*tls.Config, error) {
	if !c.TLSEnabled {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.TLSServerName,
		InsecureSkipVerify: c.TLSInsecureSkip, //nolint:gosec // intentional opt-in, warned at startup
	}

	if c.TLSCAFile != "" {
		caPEM, err := os.ReadFile(c.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read redis tls ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("append redis ca: no certificates found")
		}
		tlsCfg.RootCAs = pool
	}

	if c.TLSCertFile != "" || c.TLSKeyFile != "" {
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return nil, errors.New("REDIS_TLS_CERT_FILE and REDIS_TLS_KEY_FILE must be set together")
		}
		cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load redis tls client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func envRequired(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func envString(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envCSV(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		if fallback == nil {
			return nil
		}
		return append([]string(nil), fallback...)
	}

	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}
