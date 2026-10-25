package hostile_test

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/oauth"
)

// Attacker: someone who picks the nonce the callback is checked against, or
// the token it is checked on, at any size and in any spelling; and many of
// them at once. The library keeps no per-login state, so what must hold is
// that the comparison is exact at every length, costs nothing it should not,
// and gives the same answer no matter how many callbacks race.

func TestHostile_Nonce_comparisonIsExactAtAnySize(t *testing.T) {
	c, _ := jwksClient(t, stdJWKS(t))
	big := strings.Repeat("n", 8*1024) // a nonce claim that still fits under the token size cap
	for name, tc := range map[string]struct {
		claim, arg string
		accept     bool
	}{
		"control: equal":                       {testNonce, testNonce, true},
		"control: equal and large":             {big, big, true},
		"large claim, last byte differs":       {big, big[:len(big)-1] + "m", false},
		"large claim, argument one shorter":    {big, big[:len(big)-1], false},
		"large claim, argument one longer":     {big, big + "n", false},
		"short claim, megabyte argument":       {testNonce, strings.Repeat("n", 1<<20), false},
		"short claim, argument 8 MiB":          {testNonce, strings.Repeat("n", 8<<20), false},
		"argument is a prefix of the claim":    {testNonce + "tail", testNonce, false},
		"claim is a prefix of the argument":    {testNonce, testNonce + "tail", false},
		"composed versus decomposed accent":    {"café", "café", false},
		"case differs":                         {"Nonce", "nonce", false},
		"trailing NUL in the argument":         {testNonce, testNonce + "\x00", false},
		"leading NUL in the claim":             {"\x00" + testNonce, testNonce, false},
		"whitespace-only on both sides":        {"   ", "   ", true}, // exact match is the contract; emptiness is what is refused
		"argument empty":                       {testNonce, "", false},
		"claim empty and argument empty":       {"", "", false},
		"claim differs from the argument at 0": {"x" + testNonce, "y" + testNonce, false},
	} {
		t.Run(name, func(t *testing.T) {
			tok := signA(t, claims(tc.claim, nil))
			start := time.Now()
			got, err := c.VerifyIDToken(ctx(t), tok, tc.arg)
			if time.Since(start) > 2*time.Second {
				t.Fatalf("the comparison took %s", time.Since(start))
			}
			switch {
			case tc.accept && err != nil:
				t.Fatalf("refused: %v", err)
			case !tc.accept && err == nil:
				t.Fatalf("accepted %+v", got)
			case !tc.accept:
				mustRejectToken(t, got, err)
			}
		})
	}
}

// Many callbacks at once, all sharing one client and some sharing a nonce.
func TestHostile_Nonce_concurrentCallbacksNeverCrossTheirAnswers(t *testing.T) {
	c, srv := jwksClient(t, stdJWKS(t))
	const workers, rounds = 32, 40
	good := signA(t, claims(testNonce, nil))
	var wg sync.WaitGroup
	var wrong atomic.Int64
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				nonce := testNonce
				if (w+r)%2 == 1 {
					nonce = "someone-else" // a callback for another login, same token
				}
				_, err := c.VerifyIDToken(ctx(t), good, nonce)
				if (nonce == testNonce) != (err == nil) {
					wrong.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := wrong.Load(); n != 0 {
		t.Fatalf("%d of %d concurrent verifications gave the wrong answer", n, workers*rounds)
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("%d concurrent verifications fetched the keys %d times, want 1", workers*rounds, n)
	}
}

func TestHostile_State_concurrentAuthorizationRequestsNeverShareASecret(t *testing.T) {
	c := oidcClient(t, "https://idp.example/jwks", nil)
	const workers, each = 32, 60
	var mu sync.Mutex
	seen := map[string]bool{}
	var dup atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				r, err := c.AuthCodeURL()
				if err != nil {
					dup.Add(1)
					continue
				}
				mu.Lock()
				for _, v := range []string{r.State, r.Nonce, r.Verifier} {
					if seen[v] {
						dup.Add(1)
					}
					seen[v] = true
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if dup.Load() != 0 || len(seen) != 3*workers*each {
		t.Fatalf("%d repeated secrets or errors, %d distinct values of %d", dup.Load(), len(seen), 3*workers*each)
	}
}

// A client built twice from one Config does not share secrets either: the
// generator is the process's CSPRNG, not state held by the Client.
func TestHostile_State_twoClientsOfOneConfigDoNotRepeatEachOther(t *testing.T) {
	cfg := func(c *oauth.Config) { c.ClientID = "same" }
	a := oidcClient(t, "https://idp.example/jwks", cfg)
	b := oidcClient(t, "https://idp.example/jwks", cfg)
	seen := map[string]bool{}
	for range 200 {
		for _, c := range []*oauth.Client{a, b} {
			r, err := c.AuthCodeURL()
			if err != nil {
				t.Fatal(err)
			}
			for _, v := range []string{r.State, r.Nonce, r.Verifier} {
				if seen[v] {
					t.Fatalf("secret %q was issued twice", v)
				}
				seen[v] = true
			}
		}
	}
}
