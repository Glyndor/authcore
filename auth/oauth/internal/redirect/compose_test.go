package redirect

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestGuardClientKeepsCallerRefusal requires an allowed redirect to retain the
// caller's refusal, including the http.ErrUseLastResponse sentinel.
func TestGuardClientKeepsCallerRefusal(t *testing.T) {
	t.Parallel()
	// caller refuses every redirect without treating the response as an error.
	caller := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// guarded must preserve the refusal after the library accepts the redirect.
	guarded := GuardClient(caller)
	// err is the installed callback's decision for a same-origin HTTPS redirect.
	err := guarded.CheckRedirect(req(t, "https://provider.example/next"), []*http.Request{
		req(t, "https://provider.example/token"),
	})
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v, want http.ErrUseLastResponse", err)
	}
}

// TestGuardClientLibraryRuleRunsFirst requires a downgrade refusal before the
// caller's redirect callback can run.
func TestGuardClientLibraryRuleRunsFirst(t *testing.T) {
	t.Parallel()
	// called records whether the caller's callback was reached.
	var called bool
	// guarded combines the library policy with a permissive caller callback.
	guarded := GuardClient(&http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			called = true
			return nil
		},
	})
	// err must identify the HTTPS rule, rather than a later redirect rule.
	err := guarded.CheckRedirect(req(t, "http://provider.example/next"), []*http.Request{
		req(t, "https://provider.example/token"),
	})
	if err == nil || !strings.Contains(err.Error(), "refusing redirect to non-https") {
		t.Errorf("CheckRedirect = %v, want downgrade refusal", err)
	}
	if called {
		t.Error("caller CheckRedirect ran after a library refusal")
	}
}

// TestGuardClientInstalledCallbackEnforcesEachRule requires both client creation
// paths to enforce each redirect rule and allow a same-origin HTTPS redirect.
func TestGuardClientInstalledCallbackEnforcesEachRule(t *testing.T) {
	t.Parallel()
	// cases isolate each refusal and the final permitted hop count.
	cases := []struct {
		// name identifies the redirect rule under test.
		name string
		// from is the previous request URL used for the origin comparison.
		from string
		// to is the redirect target passed to the installed callback.
		to string
		// hops is the number of requests already in the redirect chain.
		hops int
		// want is the specific refusal fragment, or empty for acceptance.
		want string
	}{
		{
			name: "https downgrade", from: "https://provider.example/token",
			to: "http://provider.example/next", hops: 1, want: "refusing redirect to non-https",
		},
		{
			name: "cross-origin", from: "https://provider.example/token",
			to: "https://other.example/next", hops: 1, want: "refusing cross-origin redirect",
		},
		{
			name: "private address", from: "https://10.0.0.5/token",
			to: "https://10.0.0.5/next", hops: 1, want: "refusing redirect to private host",
		},
		{
			name: "hop limit", from: "https://provider.example/token",
			to: "https://provider.example/next", hops: 5, want: "too many redirects",
		},
		{
			name: "allowed same-origin https", from: "https://provider.example/token",
			to: "https://provider.example/next", hops: 4,
		},
	}
	for name, client := range map[string]*http.Client{
		"supplied client": GuardClient(&http.Client{}),
		"default client":  NewClient(),
	} {
		t.Run(name, func(t *testing.T) {
			// checkRedirect is the policy installed on the client consumers use.
			checkRedirect := client.CheckRedirect
			if checkRedirect == nil {
				t.Fatal("client has no redirect callback")
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					// via supplies enough history to reach the intended rule.
					via := make([]*http.Request, tc.hops)
					for i := range via {
						via[i] = req(t, tc.from)
					}
					// err must match the rule this case isolates.
					err := checkRedirect(req(t, tc.to), via)
					if tc.want == "" {
						if err != nil {
							t.Fatalf("allowed redirect refused: %v", err)
						}
						return
					}
					if err == nil || !strings.Contains(err.Error(), tc.want) {
						t.Fatalf("CheckRedirect = %v, want %q", err, tc.want)
					}
				})
			}
		})
	}
}

// TestGuardClientDoesNotMutateCaller requires a distinct client with the same
// transport, timeout and jar, leaving the original redirect callback intact.
func TestGuardClientDoesNotMutateCaller(t *testing.T) {
	t.Parallel()
	// jar supplies a non-nil cookie store whose identity must be preserved.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	// caller supplies every field whose value must survive the copy.
	callerTransport := &http.Transport{}
	caller := &http.Client{
		Transport: callerTransport,
		Timeout:   3 * time.Second,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// callback records the original function pointer for the mutation check.
	callback := reflect.ValueOf(caller.CheckRedirect).Pointer()
	// guarded must own the callback change while sharing the supplied resources.
	guarded := GuardClient(caller)
	if guarded == caller {
		t.Fatal("GuardClient returned the caller's client")
	}
	if caller.CheckRedirect == nil || reflect.ValueOf(caller.CheckRedirect).Pointer() != callback {
		t.Error("caller CheckRedirect was changed")
	}
	if caller.Timeout != 3*time.Second {
		t.Errorf("caller Timeout = %v, want 3s", caller.Timeout)
	}
	// The copy carries a guarded clone of the caller's transport, not the
	// caller's own, which must stay as it was.
	if _, ok := guarded.Transport.(*http.Transport); !ok || guarded.Transport == caller.Transport {
		t.Errorf("copy Transport = %T, want a clone of the caller's *http.Transport", guarded.Transport)
	}
	if caller.Transport != callerTransport {
		t.Error("caller Transport was replaced")
	}
	if guarded.Timeout != caller.Timeout {
		t.Errorf("copy Timeout = %v, want %v", guarded.Timeout, caller.Timeout)
	}
	if guarded.Jar != jar {
		t.Error("copy discarded the caller's Jar")
	}
}
