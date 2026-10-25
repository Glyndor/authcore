package urlcheck

import (
	"strings"
	"testing"
)

func TestRequireHTTPS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		raw     string
		wantErr string // substring; empty means accepted
	}{
		{"https://provider.example/auth", ""},
		{"http://localhost:8080/cb", ""},
		{"http://127.0.0.2/cb", ""},
		{"http://provider.example/auth", "must use https"},
		{"ftp://provider.example/auth", "must use https"},
		{"https:opaque", "opaque"},
		{"https:///path", "no host"},
		{"https://bad host/", "not a valid URL"},
	}
	for _, tc := range tests {
		err := RequireHTTPS("endpoint", tc.raw)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("RequireHTTPS(%q) = %v, want nil", tc.raw, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("RequireHTTPS(%q) = %v, want error containing %q", tc.raw, err, tc.wantErr)
		}
	}
}

func TestRequireNoFragment(t *testing.T) {
	t.Parallel()
	if err := RequireNoFragment("auth", "https://p.example/auth?x=1"); err != nil {
		t.Errorf("plain URL refused: %v", err)
	}
	if err := RequireNoFragment("auth", "https://p.example/auth#frag"); err == nil {
		t.Error("URL with a fragment accepted")
	}
	if err := RequireNoFragment("auth", "https://p.example/auth#"); err == nil {
		t.Error("URL with an empty fragment marker accepted")
	}
	// Unparseable input is RequireHTTPS's to report, not this check's.
	if err := RequireNoFragment("auth", "https://bad host/"); err != nil {
		t.Errorf("unparseable URL reported here: %v", err)
	}
}
