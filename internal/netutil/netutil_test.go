package netutil

import "testing"

func TestHostOnly(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain host", "example.com", "example.com"},
		{"host with port", "example.com:8080", "example.com"},
		{"ipv6 with port", "[::1]:8080", "::1"},
		{"ipv6 without port", "[::1]", "[::1]"},
		{"XFF comma separated", "1.2.3.4, 10.0.0.1", "1.2.3.4"},
		{"XFF with port and comma", "1.2.3.4:9000, 10.0.0.1", "1.2.3.4"},
		{"empty string", "", ""},
		{"whitespace", "  example.com  ", "example.com"},
		{"ip only", "127.0.0.1", "127.0.0.1"},
		{"ip with port", "127.0.0.1:6379", "127.0.0.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HostOnly(tc.input)
			if got != tc.want {
				t.Errorf("HostOnly(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
