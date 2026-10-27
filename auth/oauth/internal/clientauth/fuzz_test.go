package clientauth_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/clientauth"
)

// fuzzAdvertised splits the list of the fuzzer into the methods it holds:
// every newline ends one. An empty list holds no method at all, and a lone
// newline holds one method with an empty name.
func fuzzAdvertised(raw string) []string {
	var methods []string
	for {
		i := strings.IndexByte(raw, '\n')
		if i < 0 {
			return methods
		}
		methods = append(methods, raw[:i])
		raw = raw[i+1:]
	}
}

// fuzzAdvertises classifies what a provider's advertised list says, from the
// contract the package documents: RFC 6749 names Basic and the OIDC discovery
// document names client_secret_basic and client_secret_post, and the names
// are compared without regard to case. Everything else is a method this
// library does not implement.
//
// The names are listed here rather than taken from the package, so a change in
// the package's vocabulary cannot quietly change the oracle.
func fuzzAdvertises(advertised []string) (basic, post bool) {
	for _, m := range advertised {
		switch strings.ToLower(m) {
		case "client_secret_basic", "basic":
			basic = true
		case "client_secret_post", "post":
			post = true
		}
	}
	return basic, post
}

// FuzzChoose drives the choice of client-authentication method with the
// advertised list of a provider's discovery document, which is remote input.
//
// The contract: a client without a secret never authenticates; a provider
// that advertises nothing gets the method this library always sent; a
// provider that advertises Basic gets Basic, and Basic wins over Post when
// it advertises both; and a provider that advertises only methods outside
// this library's pair gets none. The order of the list and the case of its
// entries change nothing.
func FuzzChoose(f *testing.F) {
	f.Add("", true)
	f.Add("", false)
	f.Add("client_secret_basic\n", true)
	f.Add("client_secret_post\n", true)
	f.Add("client_secret_basic\nclient_secret_post\n", true)
	f.Add("client_secret_post\nclient_secret_basic\n", true)
	f.Add("CLIENT_SECRET_BASIC\n", true)
	f.Add("Client_Secret_Post\n", true)
	f.Add("basic\n", true)
	f.Add("post\n", true)
	f.Add("client_secret_jwt\n", true)
	f.Add("none\n", true)
	f.Add("\n", true)
	f.Add("client_secret_basic\n", false)
	f.Add("client_secret_post\nclient_secret_jwt\n", true)

	f.Fuzz(func(t *testing.T, raw string, hasSecret bool) {
		if len(raw) > 1<<12 {
			// A list of thousands of methods is not what the contract is
			// about, and sorting one costs more than the check.
			t.Skip()
		}
		advertised := fuzzAdvertised(raw)
		got := clientauth.Choose(advertised, hasSecret)

		basic, post := fuzzAdvertises(advertised)
		switch {
		case !hasSecret:
			// A public client has no secret to send.
			if got != clientauth.None {
				t.Fatalf("Choose(%q, false) = %v, want None", advertised, got)
			}
		case len(advertised) == 0:
			// A provider that advertises nothing gets the method this
			// library always sent.
			if got != clientauth.Post {
				t.Fatalf("Choose(%q, true) = %v, want Post", advertised, got)
			}
		case basic:
			// Basic is the OIDC default and wins over Post.
			if got != clientauth.Basic {
				t.Fatalf("Choose(%q, true) = %v, want Basic", advertised, got)
			}
		case post:
			if got != clientauth.Post {
				t.Fatalf("Choose(%q, true) = %v, want Post", advertised, got)
			}
		default:
			// Only methods outside this library's pair were advertised.
			if got != clientauth.None {
				t.Fatalf("Choose(%q, true) = %v, want None", advertised, got)
			}
		}

		// The order of the advertised list changes nothing.
		sorted := slices.Clone(advertised)
		slices.Sort(sorted)
		if other := clientauth.Choose(sorted, hasSecret); other != got {
			t.Fatalf("Choose(%q, %v) = %v, but Choose(%q, %v) = %v", advertised, hasSecret, got, sorted, hasSecret, other)
		}

		// Neither does the case of its entries.
		lowered := make([]string, 0, len(advertised))
		for _, m := range advertised {
			lowered = append(lowered, strings.ToLower(m))
		}
		if other := clientauth.Choose(lowered, hasSecret); other != got {
			t.Fatalf("Choose(%q, %v) = %v, but Choose(%q, %v) = %v", advertised, hasSecret, got, lowered, hasSecret, other)
		}

		// A method this library does not implement, added to a list that
		// already has one, changes nothing either.
		if len(advertised) > 0 {
			extended := append(slices.Clone(advertised), "client_secret_jwt")
			if other := clientauth.Choose(extended, hasSecret); other != got {
				t.Fatalf("Choose(%q, %v) = %v, but Choose(%q, %v) = %v", advertised, hasSecret, got, extended, hasSecret, other)
			}
		}
	})
}
