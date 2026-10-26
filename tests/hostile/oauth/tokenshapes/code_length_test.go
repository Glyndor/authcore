package tokenshapes_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_Exchange_codeLengthIsBounded(t *testing.T) {
	srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte(`{}`)))
	c := hostiletest.TokenClient(t, srv.URL, func(cfg *oauth.Config) { cfg.ClientSecret = "s" })
	if _, err := c.Exchange(hostiletest.Ctx(t), strings.Repeat("c", 32<<20), "v"); !errors.Is(err, oauth.ErrExchange) {
		t.Errorf("err = %v, want ErrExchange", err)
	}
	if _, err := c.Exchange(hostiletest.Ctx(t), strings.Repeat("c", 8<<10+1), "v"); !errors.Is(err, oauth.ErrExchange) {
		t.Errorf("just over the bound: err = %v", err)
	}
	if hits := srv.Hits.Load(); hits != 0 {
		t.Errorf("an oversized code reached the provider (%d requests)", hits)
	}
	before := srv.Hits.Load()
	_, _ = c.Exchange(hostiletest.Ctx(t), strings.Repeat("c", 8<<10), "v")
	if hits := srv.Hits.Load() - before; hits != 1 {
		t.Errorf("a code at the bound must reach the provider once, got %d", hits)
	}
}
