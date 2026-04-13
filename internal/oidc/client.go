package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/colzphml/pkce_istio_external/internal/circuitbreaker"
)

var ErrInvalidGrant = errors.New("invalid_grant")

type Config struct {
	IssuerURL            string
	ClientID             string
	ClientSecret         string
	Scopes               []string
	HTTPTimeout          time.Duration
	ClockSkew            time.Duration
	AccessTokenAudiences []string
	// CircuitBreakerMaxFailures is the number of consecutive failures that
	// open the circuit. Zero disables the circuit breaker.
	CircuitBreakerMaxFailures int
	// CircuitBreakerTimeout is how long the circuit stays open before a
	// half-open probe is allowed.
	CircuitBreakerTimeout time.Duration
}

type Client struct {
	cfg                 Config
	httpClient          *http.Client
	oauthConfig         oauth2.Config
	idTokenVerifier     *coreoidc.IDTokenVerifier
	accessTokenVerifier *coreoidc.IDTokenVerifier
	logoutTokenVerifier *coreoidc.IDTokenVerifier
	endSessionEndpoint  string
}

type Identity struct {
	Subject           string
	Email             string
	PreferredUsername string
	Groups            []string
	Nonce             string
	KCSessionID       string
	Issuer            string
	Audience          []string
}

type TokenSet struct {
	AccessToken        string
	RefreshToken       string
	IDToken            string
	TokenType          string
	AccessTokenExpiry  time.Time
	RefreshTokenExpiry *time.Time
}

type LogoutToken struct {
	Subject     string
	KCSessionID string
}

type providerMetadata struct {
	EndSessionEndpoint string `json:"end_session_endpoint"`
}

type idTokenClaims struct {
	Subject           string        `json:"sub"`
	Email             string        `json:"email"`
	PreferredUsername string        `json:"preferred_username"`
	Nonce             string        `json:"nonce"`
	KCSessionID       string        `json:"sid"`
	Issuer            string        `json:"iss"`
	Audience          audienceClaim `json:"aud"`
	Groups            []string      `json:"groups"`
}

type accessTokenClaims struct {
	Issuer   string        `json:"iss"`
	Audience audienceClaim `json:"aud"`
	AZP      string        `json:"azp"`
	Exp      int64         `json:"exp"`
}

type backchannelLogoutClaims struct {
	Subject     string                     `json:"sub"`
	KCSessionID string                     `json:"sid"`
	Events      map[string]json.RawMessage `json:"events"`
}

type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}

	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// cbTransport wraps an http.RoundTripper with a circuit breaker.
// HTTP 5xx responses count as failures.
type cbTransport struct {
	base http.RoundTripper
	cb   *circuitbreaker.CircuitBreaker
}

func (t *cbTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := t.cb.Execute(func() error {
		var innerErr error
		resp, innerErr = t.base.RoundTrip(req)
		if innerErr != nil {
			return innerErr
		}
		if resp.StatusCode >= http.StatusInternalServerError {
			return fmt.Errorf("upstream returned %d", resp.StatusCode)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, circuitbreaker.ErrOpen) {
			return nil, fmt.Errorf("oidc provider unavailable (circuit open): %w", err)
		}
		return resp, err
	}
	return resp, nil
}

func New(ctx context.Context, cfg Config) (*Client, error) {
	var transport http.RoundTripper = http.DefaultTransport
	if cfg.CircuitBreakerMaxFailures > 0 {
		cb := circuitbreaker.New(cfg.CircuitBreakerMaxFailures, cfg.CircuitBreakerTimeout, nil)
		transport = &cbTransport{base: http.DefaultTransport, cb: cb}
	}
	httpClient := &http.Client{
		Timeout:   cfg.HTTPTimeout,
		Transport: transport,
	}
	ctx = coreoidc.ClientContext(ctx, httpClient)

	provider, err := coreoidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("create oidc provider: %w", err)
	}

	var metadata providerMetadata
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("read oidc provider metadata: %w", err)
	}

	return &Client{
		cfg:        cfg,
		httpClient: httpClient,
		oauthConfig: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		idTokenVerifier: provider.Verifier(&coreoidc.Config{
			ClientID:             cfg.ClientID,
			SupportedSigningAlgs: nil,
			Now:                  nil,
		}),
		accessTokenVerifier: provider.Verifier(&coreoidc.Config{
			SkipClientIDCheck: true,
			Now:               nil,
		}),
		logoutTokenVerifier: provider.Verifier(&coreoidc.Config{
			ClientID: cfg.ClientID,
		}),
		endSessionEndpoint: metadata.EndSessionEndpoint,
	}, nil
}

func (c *Client) AuthCodeURL(state, nonce, redirectURL, codeVerifier string) string {
	hashed := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hashed[:])

	cfg := c.oauthConfig
	cfg.RedirectURL = redirectURL

	return cfg.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		coreoidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (c *Client) ExchangeCode(ctx context.Context, redirectURL, code, codeVerifier string) (*TokenSet, *Identity, error) {
	cfg := c.oauthConfig
	cfg.RedirectURL = redirectURL
	ctx = oauth2HTTPClientContext(ctx, c.httpClient)

	token, err := cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return nil, nil, fmt.Errorf("exchange authorization code: %w", err)
	}

	tokenSet, rawIDToken, err := tokenSetFromOAuth2(token)
	if err != nil {
		return nil, nil, err
	}
	identity, err := c.verifyIdentityToken(ctx, rawIDToken)
	if err != nil {
		return nil, nil, err
	}
	if err := c.verifyAccessToken(ctx, tokenSet.AccessToken); err != nil {
		return nil, nil, err
	}

	return tokenSet, identity, nil
}

func (c *Client) Refresh(ctx context.Context, existingRefreshToken string) (*TokenSet, error) {
	ctx = oauth2HTTPClientContext(ctx, c.httpClient)
	tokenSource := c.oauthConfig.TokenSource(ctx, &oauth2.Token{RefreshToken: existingRefreshToken})
	token, err := tokenSource.Token()
	if err != nil {
		if invalidGrantError(err) {
			return nil, fmt.Errorf("%w: refresh token rejected", ErrInvalidGrant)
		}
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	tokenSet, _, err := tokenSetFromOAuth2(token)
	if err != nil {
		return nil, err
	}
	if tokenSet.RefreshToken == "" {
		tokenSet.RefreshToken = existingRefreshToken
	}
	if err := c.verifyAccessToken(ctx, tokenSet.AccessToken); err != nil {
		return nil, err
	}

	return tokenSet, nil
}

func (c *Client) VerifyIDTokenNonce(identity *Identity, expectedNonce string) error {
	if identity == nil {
		return errors.New("identity is nil")
	}
	if identity.Nonce != expectedNonce {
		return errors.New("nonce mismatch")
	}
	return nil
}

func (c *Client) BuildLogoutURL(postLogoutRedirectURL, idTokenHint string) (string, error) {
	if c.endSessionEndpoint == "" {
		return postLogoutRedirectURL, nil
	}

	parsed, err := url.Parse(c.endSessionEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse end session endpoint: %w", err)
	}
	values := parsed.Query()
	if postLogoutRedirectURL != "" {
		values.Set("post_logout_redirect_uri", postLogoutRedirectURL)
	}
	values.Set("client_id", c.cfg.ClientID)
	if idTokenHint != "" {
		values.Set("id_token_hint", idTokenHint)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func (c *Client) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutToken, error) {
	idToken, err := c.logoutTokenVerifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify logout token: %w", err)
	}

	var claims backchannelLogoutClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode logout token claims: %w", err)
	}
	if claims.Events == nil {
		return nil, errors.New("logout token missing events claim")
	}
	if _, ok := claims.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return nil, errors.New("logout token missing backchannel logout event")
	}
	if claims.KCSessionID == "" {
		return nil, errors.New("logout token missing sid")
	}

	return &LogoutToken{
		Subject:     claims.Subject,
		KCSessionID: claims.KCSessionID,
	}, nil
}

func (c *Client) verifyIdentityToken(ctx context.Context, raw string) (*Identity, error) {
	idToken, err := c.idTokenVerifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}

	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode id token claims: %w", err)
	}

	return &Identity{
		Subject:           claims.Subject,
		Email:             claims.Email,
		PreferredUsername: claims.PreferredUsername,
		Groups:            claims.Groups,
		Nonce:             claims.Nonce,
		KCSessionID:       claims.KCSessionID,
		Issuer:            claims.Issuer,
		Audience:          []string(claims.Audience),
	}, nil
}

func (c *Client) verifyAccessToken(ctx context.Context, raw string) error {
	token, err := c.accessTokenVerifier.Verify(ctx, raw)
	if err != nil {
		return fmt.Errorf("verify access token signature: %w", err)
	}

	var claims accessTokenClaims
	if err := token.Claims(&claims); err != nil {
		return fmt.Errorf("decode access token claims: %w", err)
	}
	if claims.Issuer != c.cfg.IssuerURL {
		return errors.New("access token issuer mismatch")
	}
	if time.Unix(claims.Exp, 0).Before(time.Now().Add(-c.cfg.ClockSkew)) {
		return errors.New("access token expired")
	}
	if !audienceAllowed([]string(claims.Audience), c.cfg.AccessTokenAudiences) && claims.AZP != c.cfg.ClientID {
		return errors.New("access token audience mismatch")
	}
	return nil
}

func tokenSetFromOAuth2(token *oauth2.Token) (*TokenSet, string, error) {
	if token == nil {
		return nil, "", errors.New("oauth token is nil")
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, "", errors.New("token response missing id_token")
	}

	set := &TokenSet{
		AccessToken:       token.AccessToken,
		RefreshToken:      token.RefreshToken,
		IDToken:           rawIDToken,
		TokenType:         token.TokenType,
		AccessTokenExpiry: token.Expiry,
	}

	if expiry := refreshTokenExpiry(token.Extra("refresh_expires_in"), time.Now()); expiry != nil {
		set.RefreshTokenExpiry = expiry
	}

	return set, rawIDToken, nil
}

func refreshTokenExpiry(raw any, now time.Time) *time.Time {
	switch value := raw.(type) {
	case float64:
		return refreshTokenExpirySeconds(int64(value), now)
	case int64:
		return refreshTokenExpirySeconds(value, now)
	case json.Number:
		seconds, err := value.Int64()
		if err == nil {
			return refreshTokenExpirySeconds(seconds, now)
		}
	}
	return nil
}

func refreshTokenExpirySeconds(seconds int64, now time.Time) *time.Time {
	if seconds <= 0 {
		return nil
	}
	expiry := now.Add(time.Duration(seconds) * time.Second)
	return &expiry
}

func audienceAllowed(got, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		allowedSet[item] = struct{}{}
	}
	for _, item := range got {
		if _, ok := allowedSet[item]; ok {
			return true
		}
	}
	return false
}

func oauth2HTTPClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func invalidGrantError(err error) bool {
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) {
		return false
	}

	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(retrieveErr.Body, &payload) == nil && payload.Error == "invalid_grant" {
		return true
	}
	return false
}
