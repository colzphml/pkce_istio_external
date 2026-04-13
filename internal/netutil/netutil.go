// Package netutil provides shared network utility functions.
package netutil

import (
	"net"
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
