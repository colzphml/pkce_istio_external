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

func TestNormalizeAuthority(t *testing.T) {
	tests := []struct {
		name          string
		rawAuthority  string
		scheme        string
		forwardedPort string
		wantAuthority string
		wantHost      string
		wantErr       bool
	}{
		{
			name:          "preserve non default port from host",
			rawAuthority:  "localhost:8080",
			scheme:        "http",
			wantAuthority: "localhost:8080",
			wantHost:      "localhost",
		},
		{
			name:          "append non default forwarded port",
			rawAuthority:  "app.example.com",
			scheme:        "https",
			forwardedPort: "8443",
			wantAuthority: "app.example.com:8443",
			wantHost:      "app.example.com",
		},
		{
			name:          "strip default https port",
			rawAuthority:  "app.example.com",
			scheme:        "https",
			forwardedPort: "443",
			wantAuthority: "app.example.com",
			wantHost:      "app.example.com",
		},
		{
			name:          "take first forwarded value",
			rawAuthority:  "app.example.com:8443, internal.example.com",
			scheme:        "https",
			wantAuthority: "app.example.com:8443",
			wantHost:      "app.example.com",
		},
		{
			name:         "invalid host port",
			rawAuthority: "app.example.com:",
			scheme:       "https",
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotAuthority, gotHost, err := NormalizeAuthority(tc.rawAuthority, tc.scheme, tc.forwardedPort)
			if tc.wantErr {
				if err == nil {
					t.Fatal("NormalizeAuthority() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeAuthority() error = %v", err)
			}
			if gotAuthority != tc.wantAuthority {
				t.Fatalf("NormalizeAuthority() authority = %q, want %q", gotAuthority, tc.wantAuthority)
			}
			if gotHost != tc.wantHost {
				t.Fatalf("NormalizeAuthority() host = %q, want %q", gotHost, tc.wantHost)
			}
		})
	}
}

func TestNormalizeOrigin(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "custom https port",
			input: "https://app.example.com:8443/",
			want:  "https://app.example.com:8443",
		},
		{
			name:  "default port stripped",
			input: "http://localhost:80",
			want:  "http://localhost",
		},
		{
			name:    "path rejected",
			input:   "https://app.example.com/auth",
			wantErr: true,
		},
		{
			name:    "non http scheme rejected",
			input:   "tcp://app.example.com:8443",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeOrigin(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatal("NormalizeOrigin() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeOrigin() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeOrigin() = %q, want %q", got, tc.want)
			}
		})
	}
}
