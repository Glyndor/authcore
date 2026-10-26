package redirect_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth/internal/redirect"
)

func hop(t *testing.T, target string) *http.Request {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCheckLetsAPublicIPLiteralStayOnItsOwnOrigin(t *testing.T) {
	t.Parallel()
	via := []*http.Request{hop(t, "https://203.0.113.5/token")}
	if err := redirect.Check(hop(t, "https://203.0.113.5/next"), via); err != nil {
		t.Fatalf("a same-origin hop on a public IP literal must pass, got: %v", err)
	}
}

func TestCheckRefusesAHopThatChangesSchemeEvenWithTheSamePort(t *testing.T) {
	t.Parallel()
	via := []*http.Request{hop(t, "http://provider.example:443/token")}
	err := redirect.Check(hop(t, "https://provider.example:443/next"), via)
	if err == nil || !strings.Contains(err.Error(), "cross-origin") {
		t.Fatalf("a scheme change is a cross-origin hop, got: %v", err)
	}
}

func TestNewClientCarriesTheTenSecondBound(t *testing.T) {
	t.Parallel()
	if got := redirect.NewClient().Timeout; got != 10*time.Second {
		t.Fatalf("Timeout = %v, want 10s", got)
	}
}
