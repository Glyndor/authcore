package redirect

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func request(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Request{URL: u}
}

func TestPolicy_allowPrivateLiftsTheAddressChecks(t *testing.T) {
	t.Parallel()
	via := []*http.Request{request(t, "https://10.0.0.5/token")}
	next := request(t, "https://10.0.0.5/next")
	if err := (Policy{}).Check(next, via); err == nil || !strings.Contains(err.Error(), "private host") {
		t.Errorf("default policy: %v, want the private-host refusal", err)
	}
	if err := (Policy{AllowPrivate: true}).Check(next, via); err != nil {
		t.Errorf("AllowPrivate, same origin: %v", err)
	}
	cross := request(t, "https://10.0.0.6/next")
	if err := (Policy{AllowPrivate: true}).Check(cross, via); err == nil || !strings.Contains(err.Error(), "cross-origin") {
		t.Errorf("AllowPrivate must still refuse a cross-origin hop: %v", err)
	}
}

func TestPolicy_clientsFollowThePolicyForTheirTransport(t *testing.T) {
	t.Parallel()
	if c := (Policy{}).NewClient(); c.Transport == nil {
		t.Error("the default client has no guarded transport")
	}
	if c := (Policy{AllowPrivate: true}).NewClient(); c.Transport != nil {
		t.Errorf("AllowPrivate client Transport = %T, want the standard default", c.Transport)
	}
	own := &http.Transport{}
	if c := (Policy{AllowPrivate: true}).Guard(&http.Client{Transport: own}); c.Transport != http.RoundTripper(own) {
		t.Error("AllowPrivate must leave the caller's transport alone")
	}
}

func TestCheck_refusesCredentialsOnASameOriginHop(t *testing.T) {
	t.Parallel()
	via := []*http.Request{request(t, "https://idp.example/token")}
	if err := Check(request(t, "https://user:pw@idp.example/next"), via); err == nil || strings.Contains(err.Error(), "pw") {
		t.Errorf("got %v, want a refusal that does not repeat the password", err)
	}
}
