package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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
}

type OIDCConfig struct {
	IssuerURL            string
	ClientID             string
	ClientSecret         string
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

func LoadFromEnv() (Config, error) {
	cfg := Config{
		Log: LogConfig{
			Level: envString("LOG_LEVEL", "info"),
		},
		Server: ServerConfig{
			HTTPAddr:        envString("SERVER_HTTP_ADDR", ":8080"),
			GRPCAddr:        envString("SERVER_GRPC_ADDR", ":9090"),
			ReadTimeout:     envDuration("SERVER_READ_TIMEOUT", 15*time.Second),
			WriteTimeout:    envDuration("SERVER_WRITE_TIMEOUT", 15*time.Second),
			IdleTimeout:     envDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),
			ShutdownTimeout: envDuration("SERVER_SHUTDOWN_TIMEOUT", 20*time.Second),
		},
		OIDC: OIDCConfig{
			IssuerURL:            envRequired("OIDC_ISSUER_URL"),
			ClientID:             envRequired("OIDC_CLIENT_ID"),
			ClientSecret:         envRequired("OIDC_CLIENT_SECRET"),
			Scopes:               envCSV("OIDC_SCOPES", []string{"openid", "profile", "email", "offline_access"}),
			CallbackPath:         envString("OIDC_CALLBACK_PATH", "/_auth/callback"),
			LogoutPath:           envString("OIDC_LOGOUT_PATH", "/_auth/logout"),
			PostLogoutPath:       envString("OIDC_POST_LOGOUT_PATH", "/"),
			BackchannelPath:      envString("OIDC_BACKCHANNEL_LOGOUT_PATH", "/_auth/backchannel-logout"),
			LoginPath:            envString("OIDC_LOGIN_PATH", "/_auth/login"),
			LoginStateTTL:        envDuration("OIDC_LOGIN_STATE_TTL", 10*time.Minute),
			RefreshWindow:        envDuration("OIDC_REFRESH_WINDOW", 2*time.Minute),
			HTTPTimeout:          envDuration("OIDC_HTTP_TIMEOUT", 5*time.Second),
			ClockSkew:            envDuration("OIDC_CLOCK_SKEW", 30*time.Second),
			AccessTokenAudiences: envCSV("OIDC_ACCESS_TOKEN_AUDIENCES", nil),
		},
		Redis: RedisConfig{
			Mode:             envString("REDIS_MODE", "standalone"),
			Addresses:        envCSV("REDIS_ADDRESSES", []string{"127.0.0.1:6379"}),
			MasterName:       envString("REDIS_MASTER_NAME", "mymaster"),
			Username:         envString("REDIS_USERNAME", ""),
			Password:         envString("REDIS_PASSWORD", ""),
			SentinelUsername: envString("REDIS_SENTINEL_USERNAME", ""),
			SentinelPassword: envString("REDIS_SENTINEL_PASSWORD", ""),
			DB:               envInt("REDIS_DB", 0),
			KeyPrefix:        envString("REDIS_KEY_PREFIX", "oidc:"),
			DialTimeout:      envDuration("REDIS_DIAL_TIMEOUT", 2*time.Second),
			ReadTimeout:      envDuration("REDIS_READ_TIMEOUT", 2*time.Second),
			WriteTimeout:     envDuration("REDIS_WRITE_TIMEOUT", 2*time.Second),
			PoolSize:         envInt("REDIS_POOL_SIZE", 64),
			MinIdleConns:     envInt("REDIS_MIN_IDLE_CONNS", 16),
			TLSEnabled:       envBool("REDIS_TLS_ENABLED", false),
			TLSServerName:    envString("REDIS_TLS_SERVER_NAME", ""),
			TLSInsecureSkip:  envBool("REDIS_TLS_INSECURE_SKIP_VERIFY", false),
			TLSCAFile:        envString("REDIS_TLS_CA_FILE", ""),
			TLSCertFile:      envString("REDIS_TLS_CERT_FILE", ""),
			TLSKeyFile:       envString("REDIS_TLS_KEY_FILE", ""),
			LockRefreshTTL:   envDuration("REDIS_REFRESH_LOCK_TTL", 15*time.Second),
			LockWaitTimeout:  envDuration("REDIS_REFRESH_LOCK_WAIT_TIMEOUT", 2*time.Second),
			LockPollInterval: envDuration("REDIS_REFRESH_LOCK_POLL_INTERVAL", 50*time.Millisecond),
		},
		Session: SessionConfig{
			CookieName:        envString("SESSION_COOKIE_NAME", "__Host-oidc_session"),
			CookieDomain:      envString("SESSION_COOKIE_DOMAIN", ""),
			CookieSecure:      envBool("SESSION_COOKIE_SECURE", true),
			CookieSameSite:    envString("SESSION_COOKIE_SAMESITE", "Lax"),
			MaxLifetime:       envDuration("SESSION_MAX_LIFETIME", 12*time.Hour),
			MinAccessTokenTTL: envDuration("SESSION_MIN_ACCESS_TOKEN_TTL", 10*time.Second),
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

	if len(cfg.OIDC.AccessTokenAudiences) == 0 && cfg.OIDC.ClientID != "" {
		cfg.OIDC.AccessTokenAudiences = []string{cfg.OIDC.ClientID}
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
	if len(c.Redis.Addresses) == 0 {
		errs = append(errs, errors.New("REDIS_ADDRESSES must not be empty"))
	}
	if c.Session.CookieSecure && !strings.HasPrefix(c.Session.CookieName, "__Host-") && c.Session.CookieDomain == "" {
		// no-op, __Host- is recommended but not strictly required
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

func (c RedisConfig) TLSConfig() (*tls.Config, error) {
	if !c.TLSEnabled {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.TLSServerName,
		InsecureSkipVerify: c.TLSInsecureSkip,
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

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		panic(fmt.Sprintf("invalid duration for %s: %v", key, err))
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		panic(fmt.Sprintf("invalid bool for %s: %v", key, err))
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Sprintf("invalid int for %s: %v", key, err))
	}
	return parsed
}
