package urlcheck

import (
	"strings"
	"testing"
)

func TestRequireExternal(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw           string
		allowLoopback bool
		refused       bool
	}{
		{"https://idp.example/token", false, false},
		{"https://8.8.8.8/token", false, false},
		{"https://169.254.169.254/latest", true, true},
		{"https://10.0.0.5/jwks", true, true},
		{"https://[fd00::1]/", true, true},
		{"https://100.100.100.200/", true, true},
		{"https://metadata.google.internal/", true, true},
		{"https://api.localhost/", true, true},
		{"https://LOCALHOST/", true, true},
		{"http://127.0.0.1:9/x", false, true},
		{"http://127.0.0.1:9/x", true, false},
		{"http://localhost/x", false, true},
		{"http://localhost/x", true, false},
		{"https://[::1]/x", false, true},
		{"https://[::1]/x", true, false},
		{"://bad", false, false}, // RequireHTTPS reports parse errors
	} {
		err := RequireExternal("endpoint", tc.raw, tc.allowLoopback)
		if (err != nil) != tc.refused {
			t.Errorf("RequireExternal(%q, %v) = %v, want refused=%v", tc.raw, tc.allowLoopback, err, tc.refused)
		}
	}
}

func TestRequireHTTPS_credentials(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"https://admin:hunter2@idp.example/token", "https://admin@idp.example", "https://@idp.example", "http://u:p@127.0.0.1/x"} {
		err := RequireHTTPS("endpoint", raw)
		if err == nil {
			t.Errorf("%q accepted", raw)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "admin") {
			t.Errorf("%q: the error repeats the credentials: %v", raw, err)
		}
	}
}

func TestRequireHTTPS_parseErrorDoesNotRepeatTheURL(t *testing.T) {
	t.Parallel()
	err := RequireHTTPS("endpoint", "https://idp.example/"+strings.Repeat("a", 5000)+"\x7f")
	if err == nil {
		t.Fatal("a URL with a control character was accepted")
	}
	if len(err.Error()) > 300 {
		t.Errorf("the error is %d bytes: %.80s...", len(err.Error()), err.Error())
	}
}
