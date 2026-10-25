package oauthtest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/oauthtest"
)

func TestFakeProvider_isSilentAndKeyless(t *testing.T) {
	p := oauthtest.FakeProvider{}
	_ = p.Config()
	if p.Keys() != nil {
		t.Error("FakeProvider must expose no key store")
	}
	l := p.Logger()
	l.Debug("d")
	l.Info("i")
	l.Warn("w")
	l.Error("e")
}

func TestClients_pointAtTheServer(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()

	c := oauthtest.NewClient(t, srv)
	req, err := c.AuthCodeURL()
	if err != nil || !strings.HasPrefix(req.URL, srv.URL+"/auth") {
		t.Fatalf("NewClient auth URL = %v, %v", req, err)
	}
	if tc := oauthtest.NewTokenClient(t, srv); tc.Name() != "oauth" {
		t.Errorf("NewTokenClient name = %q", tc.Name())
	}
	if oc := oauthtest.OAuth2Client(t, srv.URL); oc.Name() != "oauth" {
		t.Errorf("OAuth2Client name = %q", oc.Name())
	}
}

func TestSignedToken_verifiesAgainstTheServedKey(t *testing.T) {
	key := oauthtest.MustRSA(t)
	srv := oauthtest.JWKSServer(t, &key.PublicKey)
	defer srv.Close()

	c := oauthtest.NewClient(t, srv)
	tok := oauthtest.SignIDToken(t, key, oauthtest.KID, oauthtest.ValidClaims(srv.URL, "n"))
	claims, err := c.VerifyIDToken(context.Background(), tok, "n")
	if err != nil || claims.Subject != "user-abc" {
		t.Fatalf("VerifyIDToken = %+v, %v", claims, err)
	}
}

func TestPaddedBodies_haveTheDocumentedLengths(t *testing.T) {
	if got := len(oauthtest.PaddedBodyAt(100, `{"p":"`, `"}`)); got != 100 {
		t.Errorf("PaddedBodyAt length = %d, want 100", got)
	}
	if got := len(oauthtest.PaddedBodyOver(100, `{"p":"`, `"}`)); got != 101 {
		t.Errorf("PaddedBodyOver length = %d, want 101", got)
	}
	for name, fn := range map[string]func(){
		"at":   func() { oauthtest.PaddedBodyAt(3, "abcd", "") },
		"over": func() { oauthtest.PaddedBodyOver(3, "abcd", "") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: an oversized prefix must panic", name)
				}
			}()
			fn()
		}()
	}
}

func TestLoopbackClient_rewritesTheHostOntoTheServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://unreachable.example/ping", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := oauthtest.NewLoopbackClient(t, srv).Do(req)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
