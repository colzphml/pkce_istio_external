package model

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"
)

type LoginState struct {
	State        string    `json:"state"`
	Nonce        string    `json:"nonce"`
	CodeVerifier string    `json:"code_verifier"`
	ReturnPath   string    `json:"return_path"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	ID                 string     `json:"id"`
	Subject            string     `json:"subject"`
	Email              string     `json:"email,omitempty"`
	PreferredUsername  string     `json:"preferred_username,omitempty"`
	Groups             []string   `json:"groups,omitempty"`
	KCSessionID        string     `json:"kc_session_id,omitempty"`
	AccessToken        string     `json:"access_token"`
	RefreshToken       string     `json:"refresh_token,omitempty"`
	IDToken            string     `json:"id_token,omitempty"`
	TokenType          string     `json:"token_type,omitempty"`
	AccessTokenExpiry  time.Time  `json:"access_token_expiry"`
	RefreshTokenExpiry *time.Time `json:"refresh_token_expiry,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	Issuer             string     `json:"issuer,omitempty"`
	Audience           []string   `json:"audience,omitempty"`
}

func (s Session) NeedsRefresh(now time.Time, refreshWindow time.Duration) bool {
	if s.RefreshToken == "" {
		return false
	}
	return !s.AccessTokenExpiry.After(now.Add(refreshWindow))
}

func (s Session) CanServe(now time.Time, minAccessTokenTTL time.Duration) bool {
	return s.AccessTokenExpiry.After(now.Add(minAccessTokenTTL)) && s.ExpiresAt.After(now)
}

func (s Session) TTL(now time.Time) time.Duration {
	if !s.ExpiresAt.After(now) {
		return 0
	}
	return s.ExpiresAt.Sub(now)
}

func RandomToken(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(buf)
	if len(encoded) >= length {
		return encoded[:length], nil
	}
	return encoded, nil
}

func GroupsHeader(groups []string) string {
	if len(groups) == 0 {
		return ""
	}
	return strings.Join(groups, ",")
}
