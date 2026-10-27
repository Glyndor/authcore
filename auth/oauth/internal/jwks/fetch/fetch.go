// Package fetch downloads a provider's JWKS document and turns it into the set
// of signing-key candidates the cache selects from.
package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Glyndor/authcore/auth/oauth/internal/jsonstrict"
	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/candidate"
	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/jwk"
)

// MaxBytes caps a JWKS response so a hostile endpoint cannot exhaust memory.
const MaxBytes = 1 << 20

type jwksDoc struct {
	// Keys holds the raw text of every key of the document, so each one can
	// be read on its own terms before it becomes a JWK.
	Keys []json.RawMessage `json:"keys"`
}

// Set is the usable content of one JWKS response.
type Set struct {
	// Keys maps each kid to its candidates. When AnonAvailable, the one key
	// without a kid is stored under the empty kid.
	Keys map[string][]candidate.Candidate
	// AnonAvailable is true when the set has exactly one key with no kid.
	AnonAvailable bool
}

// Get fetches the JWKS at url with h. An HTTP 200 with zero usable keys is an
// authoritative empty set, not an error. Every failure wraps errFetch, except
// that a cancelled or expired ctx is returned as the context error itself.
//
// failed is called once for each failure that should count as a refresh
// attempt against the provider: it is not called when the request cannot be
// built or when ctx ended, because neither says anything about the provider.
func Get(ctx context.Context, h *http.Client, url string, errFetch error, failed func()) (Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Set{}, fmt.Errorf("%w: build request: %w", errFetch, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.Do(req)
	if err != nil {
		// Do not treat a cancellation of the caller's context as a refresh
		// failure. Return the context error without recording lastAttempt, so
		// the next caller with a live context can try again immediately
		// instead of being blocked by a minute-long cooldown.
		//
		// The test is the caller's context, not the error: the HTTP client's
		// own timeout also satisfies errors.Is(err, context.DeadlineExceeded),
		// and that one says the provider did not answer, which must count.
		if ctx.Err() != nil {
			return Set{}, ctx.Err()
		}
		failed()
		return Set{}, fmt.Errorf("%w: %w", errFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read one byte past the cap: a body that does not fit is refused whole,
	// never read as the prefix that does fit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return Set{}, ctx.Err()
		}
		failed()
		return Set{}, fmt.Errorf("%w: read: %w", errFetch, err)
	}
	if len(body) > MaxBytes {
		failed()
		return Set{}, fmt.Errorf("%w: response larger than %d bytes", errFetch, MaxBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		failed()
		return Set{}, fmt.Errorf("%w: status %d", errFetch, resp.StatusCode)
	}

	var members struct {
		Keys jsonstrict.Once `json:"keys"`
	}
	if err := json.Unmarshal(body, &members); err != nil {
		failed()
		return Set{}, fmt.Errorf("%w: decode: %w", errFetch, err)
	}
	if members.Keys.Twice() {
		failed()
		return Set{}, fmt.Errorf("%w: keys is written more than once", errFetch)
	}
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		failed()
		return Set{}, fmt.Errorf("%w: decode: %w", errFetch, err)
	}
	return build(doc), nil
}

// build keeps the keys eligible to verify a signature, grouped by kid.
func build(doc jwksDoc) Set {
	keys := make(map[string][]candidate.Candidate, len(doc.Keys))
	var anon []candidate.Candidate
	for _, raw := range doc.Keys {
		k, err := jwk.Decode(raw)
		if err != nil {
			continue // skip keys we cannot use (unsupported type/curve, members read two ways); others remain usable
		}
		// Only signature keys are eligible. A key explicitly published for
		// encryption must never be selected to verify a token signature.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := jwk.Parse(k)
		if err != nil {
			continue // skip keys we cannot use (unsupported type/curve); others remain usable
		}
		cand := candidate.Candidate{Pub: pub, Alg: k.Alg, Use: k.Use, Issuer: k.Issuer}
		if len(k.KeyOps) > 0 {
			cand.KeyOps = make(map[string]struct{}, len(k.KeyOps))
			for _, op := range k.KeyOps {
				cand.KeyOps[op] = struct{}{}
			}
		}
		if k.Kid != "" {
			keys[k.Kid] = append(keys[k.Kid], cand)
		} else {
			anon = append(anon, cand)
		}
	}

	// Treat an empty key set as authoritative. The provider publishes that the
	// keys are gone: the caller replaces its cache with the empty set rather
	// than serving the previous entry, so lookups fail closed.
	anonAvailable := len(anon) == 1 && len(keys) == 0
	if anonAvailable {
		keys[""] = anon
	}
	return Set{Keys: keys, AnonAvailable: anonAvailable}
}
