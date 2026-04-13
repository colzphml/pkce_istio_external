// Package netutil provides shared network utility functions.
package netutil

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// HostOnly extracts the hostname from a host:port string, an IPv6 address, or
// a comma-separated X-Forwarded-For / X-Forwarded-Host value. It returns only
// the first (leftmost) host component without a port suffix.
func HostOnly(hostport string) string {
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

// FirstForwardedValue returns the first value from a comma-separated forwarded
// header such as X-Forwarded-Host or X-Forwarded-Port.
func FirstForwardedValue(value string) string {
	return strings.TrimSpace(strings.Split(value, ",")[0])
}

// NormalizeAuthority returns a canonical URL authority from a raw host header
// value and an optional forwarded port. Default ports for http/https are
// stripped, while non-default ports are preserved.
func NormalizeAuthority(rawAuthority, scheme, forwardedPort string) (string, string, error) {
	host, port, err := splitAuthority(rawAuthority)
	if err != nil {
		return "", "", err
	}
	if host == "" {
		return "", "", nil
	}

	if port == "" {
		port = normalizedPort(forwardedPort)
	}
	if port != "" && port == defaultPortForScheme(scheme) {
		port = ""
	}

	return formatAuthority(host, port), host, nil
}

// NormalizeOrigin validates and canonicalizes an origin string. It accepts only
// http/https origins without path/query/fragment and strips default ports.
func NormalizeOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", errors.New("host is required")
	}
	if parsed.User != nil {
		return "", errors.New("userinfo is not allowed")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("query and fragment are not allowed")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errors.New("path is not allowed in origin")
	}

	authority, _, err := NormalizeAuthority(parsed.Host, parsed.Scheme, "")
	if err != nil {
		return "", err
	}
	if authority == "" {
		return "", errors.New("host is required")
	}
	return parsed.Scheme + "://" + authority, nil
}

func splitAuthority(raw string) (string, string, error) {
	authority := FirstForwardedValue(raw)
	if authority == "" {
		return "", "", nil
	}

	if strings.HasPrefix(authority, "[") {
		if strings.HasSuffix(authority, "]") {
			return strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]"), "", nil
		}
		host, port, err := net.SplitHostPort(authority)
		if err != nil {
			return "", "", err
		}
		if port == "" {
			return "", "", errors.New("port is required after colon")
		}
		return host, port, nil
	}

	if strings.Count(authority, ":") == 1 {
		host, port, err := net.SplitHostPort(authority)
		if err != nil {
			return "", "", err
		}
		if port == "" {
			return "", "", errors.New("port is required after colon")
		}
		return host, port, nil
	}

	if strings.Count(authority, ":") > 1 {
		return authority, "", nil
	}

	return authority, "", nil
}

func normalizedPort(raw string) string {
	port := FirstForwardedValue(raw)
	if !validPort(port) {
		return ""
	}
	return port
}

func validPort(raw string) bool {
	if raw == "" {
		return false
	}
	port, err := strconv.Atoi(raw)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
}

func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func formatAuthority(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}
