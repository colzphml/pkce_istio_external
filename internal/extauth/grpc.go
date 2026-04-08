package extauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/colzphml/pkce_istio_external/internal/config"
	"github.com/colzphml/pkce_istio_external/internal/model"
	"github.com/colzphml/pkce_istio_external/internal/session"
	"github.com/colzphml/pkce_istio_external/internal/telemetry"
)

type SessionManager interface {
	GetSession(context.Context, string) (*model.Session, error)
	EnsureFresh(context.Context, *model.Session) (*model.Session, error)
	IdentityHeaders(*model.Session) session.SessionIdentity
	ClearSessionCookie() *http.Cookie
}

type Server struct {
	authv3.UnimplementedAuthorizationServer
	manager *session.Manager
	cfg     config.Config
	logger  *slog.Logger
	metrics *telemetry.Metrics
}

func NewServer(manager *session.Manager, cfg config.Config, logger *slog.Logger, metrics *telemetry.Metrics) *Server {
	return &Server{
		manager: manager,
		cfg:     cfg,
		logger:  logger,
		metrics: metrics,
	}
}

func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	start := time.Now()
	decision := "error"
	defer func() {
		s.metrics.AuthzChecksTotal.WithLabelValues(decision).Inc()
		s.metrics.AuthzCheckDuration.Observe(time.Since(start).Seconds())
	}()

	httpAttrs := req.GetAttributes().GetRequest().GetHttp()
	if httpAttrs == nil {
		decision = "deny_error"
		return denyResponse(http.StatusInternalServerError, "missing http attributes", nil), nil
	}

	path := firstNonEmpty(httpAttrs.GetHeaders()[":path"], httpAttrs.GetPath())
	if path == "" {
		path = "/"
	}
	if path == "/_auth" || strings.HasPrefix(path, "/_auth/") {
		decision = "allow_bypass"
		return allowResponse(nil), nil
	}

	headers := normalizeHeaders(httpAttrs.GetHeaders())
	host := firstNonEmpty(headers["x-forwarded-host"], headers[":authority"], headers["host"], httpAttrs.GetHost())
	if !s.hostAllowed(host) {
		decision = "deny_host"
		return denyResponse(http.StatusForbidden, "host is not allowed", nil), nil
	}

	sessionID, err := cookieValue(headers["cookie"], s.cfg.Session.CookieName)
	if err != nil || sessionID == "" {
		decision = "redirect_login"
		return redirectToLogin(path, false, s.cfg, nil), nil
	}

	sess, err := s.manager.GetSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, session.ErrSessionExpired) {
			decision = "redirect_expired"
			return redirectToLogin(path, true, s.cfg, s.manager.ClearSessionCookie()), nil
		}
		s.logger.Error("failed to load session", "error", err)
		decision = "deny_error"
		return denyResponse(http.StatusServiceUnavailable, "session lookup failed", nil), nil
	}

	sess, err = s.manager.EnsureFresh(ctx, sess)
	if err != nil {
		if errors.Is(err, session.ErrSessionExpired) {
			decision = "redirect_refresh_expired"
			return redirectToLogin(path, true, s.cfg, s.manager.ClearSessionCookie()), nil
		}
		s.logger.Error("failed to ensure fresh session", "error", err)
		decision = "deny_error"
		return denyResponse(http.StatusServiceUnavailable, "token refresh failed", nil), nil
	}

	identity := s.manager.IdentityHeaders(sess)
	headersToAdd := []*corev3.HeaderValueOption{
		headerValueOption(s.cfg.Headers.AuthorizationHeader, identity.AuthorizationValue),
		headerValueOption(s.cfg.Headers.UserHeader, identity.UserHeaderValue),
		headerValueOption(s.cfg.Headers.EmailHeader, identity.EmailHeaderValue),
		headerValueOption(s.cfg.Headers.SubjectHeader, identity.SubjectHeaderValue),
		headerValueOption(s.cfg.Headers.PreferredUsernameHeader, identity.PreferredUsernameValue),
	}
	if identity.GroupsHeaderValue != "" {
		headersToAdd = append(headersToAdd, headerValueOption(s.cfg.Headers.GroupsHeader, identity.GroupsHeaderValue))
	}

	decision = "allow"
	return allowResponse(headersToAdd), nil
}

func normalizeHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[strings.ToLower(key)] = value
	}
	return out
}

func allowResponse(headers []*corev3.HeaderValueOption) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: headers,
			},
		},
	}
}

func denyResponse(code int, body string, headers []*corev3.HeaderValueOption) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode(code)},
				Headers: headers,
				Body:    body,
			},
		},
	}
}

func redirectToLogin(path string, clearCookie bool, cfg config.Config, clear *http.Cookie) *authv3.CheckResponse {
	location := cfg.OIDC.LoginPath + "?return_url=" + url.QueryEscape(path)
	headers := []*corev3.HeaderValueOption{
		headerValueOption("location", location),
	}
	if clearCookie && clear != nil {
		headers = append(headers, headerValueOption("set-cookie", clear.String()))
	}
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Found},
				Headers: headers,
			},
		},
	}
}

func cookieValue(rawCookieHeader, cookieName string) (string, error) {
	if rawCookieHeader == "" {
		return "", http.ErrNoCookie
	}

	req := &http.Request{Header: http.Header{"Cookie": []string{rawCookieHeader}}}
	cookie, err := req.Cookie(cookieName)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func headerValueOption(key, value string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   key,
			Value: value,
		},
	}
}

func (s *Server) hostAllowed(host string) bool {
	host = hostOnly(host)
	if len(s.cfg.Session.AllowedHosts) == 0 {
		return true
	}
	for _, allowed := range s.cfg.Session.AllowedHosts {
		allowed = hostOnly(allowed)
		if allowed == host {
			return true
		}
		if strings.HasPrefix(allowed, "*.") && strings.HasSuffix(host, strings.TrimPrefix(allowed, "*")) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func hostOnly(hostport string) string {
	hostport = strings.TrimSpace(strings.Split(hostport, ",")[0])
	if strings.HasPrefix(hostport, "[") {
		if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
			return parsedHost
		}
	}
	if strings.Count(hostport, ":") == 1 {
		if parsedHost, _, err := net.SplitHostPort(hostport); err == nil {
			return parsedHost
		}
	}
	return hostport
}

func StatusCode(code int) typev3.StatusCode {
	return typev3.StatusCode(code)
}

func RedirectLoginLocation(loginPath, path string) string {
	return fmt.Sprintf("%s?return_url=%s", loginPath, url.QueryEscape(path))
}
