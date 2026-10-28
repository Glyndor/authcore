package idtoken

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"unicode"
)

func TestVerifyBoundsRemoteNumericParserErrors(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	const canary = "314159265358979323846264338327950288419716939937510"
	body := `{"extra":` + strings.Repeat("7", 7000) + canary + `}`
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(body)) + ".AA"
	_, err := Verify(context.Background(), f.params(), token, testNonce)
	if !errors.Is(err, errInvalid) {
		t.Fatalf("error = %v, want invalid sentinel", err)
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if len(cause.Error()) > 1024 || strings.Contains(cause.Error(), canary) {
			t.Fatalf("parser diagnostic retains remote number: %d bytes", len(cause.Error()))
		}
		for _, r := range cause.Error() {
			if !unicode.IsPrint(r) {
				t.Fatalf("nonprintable diagnostic rune %U", r)
			}
		}
	}
	if _, err := Verify(context.Background(), f.params(), f.sign(t, goodClaims()), testNonce); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPreservesKeySelectionErrorCauses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	fetch, stale := errors.New("fetch"), errors.New("stale")
	for _, cause := range []error{fetch, errors.Join(fetch, stale), context.Canceled, context.DeadlineExceeded} {
		p := f.params()
		p.Keys = fixedKeys{err: cause}
		_, err := Verify(context.Background(), p, f.sign(t, goodClaims()), testNonce)
		if !errors.Is(err, errInvalid) || !errors.Is(err, cause) {
			t.Errorf("key selection cause lost: %v, want %v", err, cause)
		}
		if errors.Is(cause, stale) && (!errors.Is(err, stale) || !errors.Is(err, fetch)) {
			t.Errorf("stale/fetch identity lost: %v", err)
		}
	}
}

func TestParseErrorSeparatesRemoteDiagnosticsFromKeyCauses(t *testing.T) {
	t.Parallel()
	remote := errors.New("parser\n" + strings.Repeat("x", 7000) + "REMOTE_CANARY")
	for _, keyErr := range []error{nil, context.Canceled, context.DeadlineExceeded} {
		err := parseError(errInvalid, remote, keyErr)
		if !errors.Is(err, errInvalid) {
			t.Fatalf("invalid sentinel lost: %v", err)
		}
		if errors.Is(err, remote) || len(err.Error()) > 1024 || strings.Contains(err.Error(), "REMOTE_CANARY") || strings.ContainsAny(err.Error(), "\r\n") {
			t.Fatalf("remote parser cause retained: %d bytes", len(err.Error()))
		}
		if keyErr != nil && !errors.Is(err, keyErr) {
			t.Fatalf("key cause lost: %v", err)
		}
	}
}
