package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// ---- audienceClaim.UnmarshalJSON ----

func TestAudienceClaim_UnmarshalJSON_Single(t *testing.T) {
	var a audienceClaim
	if err := json.Unmarshal([]byte(`"my-client"`), &a); err != nil {
		t.Fatalf("UnmarshalJSON single: %v", err)
	}
	if len(a) != 1 || a[0] != "my-client" {
		t.Fatalf("got %v, want [my-client]", a)
	}
}

func TestAudienceClaim_UnmarshalJSON_Array(t *testing.T) {
	var a audienceClaim
	if err := json.Unmarshal([]byte(`["aud1","aud2"]`), &a); err != nil {
		t.Fatalf("UnmarshalJSON array: %v", err)
	}
	if len(a) != 2 || a[0] != "aud1" || a[1] != "aud2" {
		t.Fatalf("got %v, want [aud1 aud2]", a)
	}
}

func TestAudienceClaim_UnmarshalJSON_Empty(t *testing.T) {
	var a audienceClaim
	if err := json.Unmarshal([]byte(`[]`), &a); err != nil {
		t.Fatalf("UnmarshalJSON empty array: %v", err)
	}
	if len(a) != 0 {
		t.Fatalf("got %v, want empty", a)
	}
}

// ---- audienceAllowed ----

func TestAudienceAllowed(t *testing.T) {
	tests := []struct {
		got     []string
		allowed []string
		want    bool
	}{
		{[]string{"a"}, []string{}, true},         // empty allowed list → all OK
		{[]string{"a"}, nil, true},                // nil allowed list → all OK
		{[]string{"a"}, []string{"a"}, true},      // match
		{[]string{"a"}, []string{"b"}, false},     // no match
		{[]string{"a", "b"}, []string{"b"}, true}, // one of many matches
		{[]string{}, []string{"a"}, false},        // empty got, non-empty allowed
	}

	for _, tc := range tests {
		got := audienceAllowed(tc.got, tc.allowed)
		if got != tc.want {
			t.Errorf("audienceAllowed(%v, %v) = %v, want %v", tc.got, tc.allowed, got, tc.want)
		}
	}
}

// ---- invalidGrantError ----

func TestInvalidGrantError_True(t *testing.T) {
	body := []byte(`{"error":"invalid_grant","error_description":"Token expired"}`)
	err := &oauth2.RetrieveError{Body: body, ErrorCode: "invalid_grant"}
	if !invalidGrantError(err) {
		t.Fatal("invalidGrantError() = false for invalid_grant, want true")
	}
}

func TestInvalidGrantError_False_WrongCode(t *testing.T) {
	body := []byte(`{"error":"access_denied"}`)
	err := &oauth2.RetrieveError{Body: body, ErrorCode: "access_denied"}
	if invalidGrantError(err) {
		t.Fatal("invalidGrantError() = true for access_denied, want false")
	}
}

func TestInvalidGrantError_False_NonRetrieveError(t *testing.T) {
	if invalidGrantError(errors.New("generic error")) {
		t.Fatal("invalidGrantError() = true for generic error, want false")
	}
}

// ---- tokenSetFromOAuth2 ----

func TestTokenSetFromOAuth2_NilToken(t *testing.T) {
	_, _, err := tokenSetFromOAuth2(nil)
	if err == nil {
		t.Fatal("tokenSetFromOAuth2(nil) = nil, want error")
	}
}

func TestTokenSetFromOAuth2_MissingIDToken(t *testing.T) {
	token := (&oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
	}).WithExtra(map[string]interface{}{})
	_, _, err := tokenSetFromOAuth2(token)
	if err == nil {
		t.Fatal("tokenSetFromOAuth2() missing id_token = nil, want error")
	}
}

func TestTokenSetFromOAuth2_Float64RefreshExpiry(t *testing.T) {
	before := time.Now()
	token := (&oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(30 * time.Minute),
	}).WithExtra(map[string]interface{}{
		"id_token":           "idtoken",
		"refresh_expires_in": float64(3600),
	})
	set, _, err := tokenSetFromOAuth2(token)
	if err != nil {
		t.Fatalf("tokenSetFromOAuth2() error = %v", err)
	}
	if set.RefreshTokenExpiry == nil {
		t.Fatal("RefreshTokenExpiry = nil, want non-nil")
	}
	lowerBound := before.Add(3600 * time.Second)
	if set.RefreshTokenExpiry.Before(lowerBound.Add(-2 * time.Second)) {
		t.Fatalf("RefreshTokenExpiry = %v, too early (expected around %v)", set.RefreshTokenExpiry, lowerBound)
	}
}

func TestTokenSetFromOAuth2_JSONNumberRefreshExpiry(t *testing.T) {
	token := (&oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		Expiry:       time.Now().Add(30 * time.Minute),
	}).WithExtra(map[string]interface{}{
		"id_token":           "idtoken",
		"refresh_expires_in": json.Number("1800"),
	})
	set, _, err := tokenSetFromOAuth2(token)
	if err != nil {
		t.Fatalf("tokenSetFromOAuth2() error = %v", err)
	}
	if set.RefreshTokenExpiry == nil {
		t.Fatal("RefreshTokenExpiry = nil, want non-nil")
	}
}

func TestTokenSetFromOAuth2_NonPositiveRefreshExpiryIgnored(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
	}{
		{name: "float64 zero", value: float64(0)},
		{name: "int64 zero", value: int64(0)},
		{name: "json number zero", value: json.Number("0")},
		{name: "negative", value: int64(-1)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := (&oauth2.Token{
				AccessToken:  "access",
				RefreshToken: "refresh",
				Expiry:       time.Now().Add(30 * time.Minute),
			}).WithExtra(map[string]interface{}{
				"id_token":           "idtoken",
				"refresh_expires_in": tc.value,
			})
			set, _, err := tokenSetFromOAuth2(token)
			if err != nil {
				t.Fatalf("tokenSetFromOAuth2() error = %v", err)
			}
			if set.RefreshTokenExpiry != nil {
				t.Fatalf("RefreshTokenExpiry = %v, want nil", set.RefreshTokenExpiry)
			}
		})
	}
}

// ---- VerifyIDTokenNonce ----

func TestVerifyIDTokenNonce_NilIdentity(t *testing.T) {
	c := &Client{}
	if err := c.VerifyIDTokenNonce(nil, "nonce"); err == nil {
		t.Fatal("VerifyIDTokenNonce(nil) = nil, want error")
	}
}

func TestVerifyIDTokenNonce_Mismatch(t *testing.T) {
	c := &Client{}
	identity := &Identity{Nonce: "actual-nonce"}
	if err := c.VerifyIDTokenNonce(identity, "expected-nonce"); err == nil {
		t.Fatal("VerifyIDTokenNonce() mismatch = nil, want error")
	}
}

func TestVerifyIDTokenNonce_Match(t *testing.T) {
	c := &Client{}
	identity := &Identity{Nonce: "correct-nonce"}
	if err := c.VerifyIDTokenNonce(identity, "correct-nonce"); err != nil {
		t.Fatalf("VerifyIDTokenNonce() match error = %v", err)
	}
}

// ---- BuildLogoutURL ----

func TestBuildLogoutURL_EmptyEndpoint(t *testing.T) {
	c := &Client{endSessionEndpoint: ""}
	url, err := c.BuildLogoutURL("https://app.example.com/", "")
	if err != nil {
		t.Fatalf("BuildLogoutURL() empty endpoint error = %v", err)
	}
	if url != "https://app.example.com/" {
		t.Fatalf("BuildLogoutURL() = %q, want passthrough", url)
	}
}

func TestBuildLogoutURL_WithEndpoint(t *testing.T) {
	c := &Client{
		cfg:                Config{ClientID: "my-client"},
		endSessionEndpoint: "https://keycloak.example.com/realms/main/protocol/openid-connect/logout",
	}
	url, err := c.BuildLogoutURL("https://app.example.com/", "id-token-hint")
	if err != nil {
		t.Fatalf("BuildLogoutURL() error = %v", err)
	}
	if url == "" {
		t.Fatal("BuildLogoutURL() = empty")
	}
	_ = fmt.Sprintf("got: %s", url)
	if !containsParam(url, "id_token_hint", "id-token-hint") {
		t.Fatalf("BuildLogoutURL() missing id_token_hint in %q", url)
	}
	if !containsParam(url, "client_id", "my-client") {
		t.Fatalf("BuildLogoutURL() missing client_id in %q", url)
	}
}

func containsParam(rawURL, key, value string) bool {
	return len(rawURL) > 0 && (containsStr(rawURL, key+"="+value) || containsStr(rawURL, key+"="+urlEncode(value)))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func urlEncode(s string) string {
	return (&oauth2.Config{}).AuthCodeURL(s)[:0] + s
}
