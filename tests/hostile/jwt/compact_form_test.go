package jwt_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/jwt"
)

const base64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// Compact serialization is three base64url segments joined by dots. Every
// other spelling of the same bytes is refused: one token, one spelling.
func TestHostile_CompactForm_malformedSerializationsAreRefused(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	good := e.signEdDSA(t, nil, claimsFor("access"))
	if _, err := m.VerifyAccessToken(good); err != nil {
		t.Fatalf("control token refused: %v", err)
	}
	h, p, s := split3(t, good)

	cases := map[string]string{
		"empty":                    "",
		"one dot":                  ".",
		"two dots":                 "..",
		"three dots":               "...",
		"two segments":             h + "." + p,
		"four segments":            good + ".AAAA",
		"leading dot":              "." + good,
		"trailing dot":             good + ".",
		"double dot after header":  h + ".." + s,
		"double dot after payload": h + "." + p + ".." + s,
		"empty payload":            h + ".." + s,
		"empty header":             "." + p + "." + s,
		"empty signature":          h + "." + p + ".",
		"leading space":            " " + good,
		"trailing space":           good + " ",
		"trailing newline":         good + "\n",
		"trailing CRLF":            good + "\r\n",
		"space inside":             good[:20] + " " + good[20:],
		"tab inside":               good[:20] + "\t" + good[20:],
		"NUL inside":               good[:20] + "\x00" + good[20:],
		"NUL at end":               good + "\x00",
		"Bearer prefix":            "Bearer " + good,
		"bearer prefix no space":   "Bearer" + good,
		"JWT prefix":               "JWT " + good,
		"quoted":                   `"` + good + `"`,
		"url encoded dot":          strings.Replace(good, ".", "%2E", 1),
		"padded header":            h + "==." + p + "." + s,
		"padded signature":         h + "." + p + "." + s + "==",
		"std base64 plus":          h + "." + strings.Replace(p, "A", "+", 1) + "." + s,
		"std base64 slash":         h + "." + strings.Replace(p, "A", "/", 1) + "." + s,
		"non-ASCII letter":         h + "." + p + "\u00e9." + s,
		"fullwidth letter":         h + "." + p + "\uff21." + s,
		"zero width space":         h + "\u200b." + p + "." + s,
		"JSON serialization":       `{"payload":"` + p + `","protected":"` + h + `","signature":"` + s + `"}`,
		"JWS flattened array":      `[` + good + `]`,
		"single character":         "a",
		"only dots and letters":    "a.b.c",
		"high bytes":               string([]byte{0xff, 0xfe, '.', 0xff, '.', 0xff}),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := m.VerifyAccessToken(token)
			if c != nil || !isInvalidOrMalformed(err) {
				t.Fatalf("VerifyAccessToken = %+v, %v; want nil and ErrTokenInvalid or ErrTokenMalformed", c, err)
			}
		})
	}
}

// Non-canonical base64url: the last character of a segment carries unused
// bits. A strict decoder refuses a spelling that decodes to the same bytes
// with those bits set, so a signature cannot be replayed under a second
// spelling that evades a blocklist keyed on the token string.
func TestHostile_CompactForm_nonCanonicalTrailingBitsAreRefused(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	good := e.signEdDSA(t, nil, claimsFor("access"))
	h, p, s := split3(t, good)

	// An Ed25519 signature is 64 bytes: 86 base64 characters, the last of
	// which carries 4 unused bits. Flip each of them in turn.
	last := s[len(s)-1]
	idx := strings.IndexByte(base64urlAlphabet, last)
	flipped := 0
	for bit := 0; bit < 4; bit++ {
		alt := base64urlAlphabet[idx^(1<<bit)]
		token := h + "." + p + "." + s[:len(s)-1] + string(alt)
		if c, err := m.VerifyAccessToken(token); c != nil || err == nil {
			t.Fatalf("signature spelled with unused bit %d set was accepted", bit)
		}
		flipped++
	}
	if flipped != 4 {
		t.Fatalf("flipped %d bits, want 4", flipped)
	}
}

// Changing any single character of a valid token makes it invalid. The
// signature covers header and payload as spelled, and the last signature
// character is covered by the strict decoding above, so no position is slack.
func TestHostile_CompactForm_everySingleCharacterChangeIsRefused(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	good := e.signEdDSA(t, nil, claimsFor("access"))
	if _, err := m.VerifyAccessToken(good); err != nil {
		t.Fatalf("control token refused: %v", err)
	}
	for i := 0; i < len(good); i++ {
		if good[i] == '.' {
			continue
		}
		pos := strings.IndexByte(base64urlAlphabet, good[i])
		for _, alt := range []byte{base64urlAlphabet[(pos+1)%64], base64urlAlphabet[(pos+32)%64]} {
			token := good[:i] + string(alt) + good[i+1:]
			if c, err := m.VerifyAccessToken(token); c != nil || err == nil {
				t.Fatalf("token with character %d changed %q -> %q was accepted", i, good[i], alt)
			}
		}
	}
}

// A truncated signature, or one padded with extra bytes, is not a signature.
func TestHostile_CompactForm_signatureLengthIsExact(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	good := e.signEdDSA(t, nil, claimsFor("access"))
	h, p, s := split3(t, good)
	for name, sig := range map[string]string{
		"one char short":  s[:len(s)-1],
		"half":            s[:len(s)/2],
		"one char":        s[:1],
		"doubled":         s + s,
		"one extra block": s + "AAAA",
		"all A":           strings.Repeat("A", len(s)),
		"all zero bytes":  strings.Repeat("A", 86),
	} {
		token := h + "." + p + "." + sig
		if c, err := m.VerifyAccessToken(token); c != nil || err == nil {
			t.Errorf("%s: signature accepted", name)
		}
	}
}

// The size cap is 8 KiB on the token string and is checked before any decoding.
func TestHostile_CompactForm_oversizedTokensAreRefusedBeforeParsing(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	const limit = 8 * 1024

	// A token padded to the byte limit through a signed claim: 8192 is a
	// length base64 can hit exactly, and the cap is inclusive.
	atLimit := tokenOfLength(t, e, limit)
	if c, err := m.VerifyAccessToken(atLimit); err != nil {
		t.Fatalf("a token of exactly %d bytes was refused: %v (%+v)", limit, err, c)
	}
	over := tokenOfLength(t, e, limit+2)
	if c, err := m.VerifyAccessToken(over); c != nil || !errors.Is(err, jwt.ErrTokenOversized) {
		t.Fatalf("a token of %d bytes = %+v, %v; want ErrTokenOversized", len(over), c, err)
	}
	if p, err := m.RotateTokens(tokenOfLengthTyped(t, e, limit+2, "refresh"), extra{}); p != nil || !errors.Is(err, jwt.ErrTokenOversized) {
		t.Fatalf("an oversized refresh token = %+v, %v; want ErrTokenOversized", p, err)
	}

	for name, size := range map[string]int{"64 KiB": 64 << 10, "1 MiB": 1 << 20, "32 MiB": 32 << 20} {
		huge := strings.Repeat("A", size)
		start := time.Now()
		c, err := m.VerifyAccessToken(huge)
		if c != nil || !errors.Is(err, jwt.ErrTokenOversized) {
			t.Errorf("%s: %+v, %v; want ErrTokenOversized", name, c, err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s: refusing took %v, want a length check", name, d)
		}
	}
}

// The module will not issue a token it would then refuse: a payload that
// pushes either token past the cap fails at CreateTokens.
func TestHostile_CompactForm_issuingRefusesOversizedTokens(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	pair, err := m.CreateTokens(subject, extra{Role: strings.Repeat("A", 9000)})
	if pair != nil || !errors.Is(err, jwt.ErrTokenOversized) {
		t.Fatalf("CreateTokens with a 9000 byte role = %+v, %v; want ErrTokenOversized", pair, err)
	}
	if _, err := m.CreateTokens(subject, extra{Role: strings.Repeat("A", 4000)}); err != nil {
		t.Fatalf("a 4000 byte role is within the cap: %v", err)
	}
}

// Deep nesting inside the 8 KiB budget does not blow the stack or hang, and
// shapes the extra payload cannot hold are refused.
func TestHostile_CompactForm_deeplyNestedPayloadIsBounded(t *testing.T) {
	e := newEnv(t)
	m := e.module(t, jwt.Config{})
	for name, nested := range map[string]string{
		"arrays":  strings.Repeat("[", 3000) + strings.Repeat("]", 3000),
		"objects": strings.Repeat(`{"a":`, 600) + "1" + strings.Repeat("}", 600),
		"open":    strings.Repeat("[", 5000),
	} {
		now := time.Now().Unix()
		payload := `{"iss":"` + jwt.DefaultConfig().Issuer + `","aud":"` + jwt.DefaultConfig().Audience[0] + `","sub":"` + subject +
			`","jti":"` + jtiA + `","iat":` + itoa(now-1) + `,"exp":` + itoa(now+600) + `,"type":"access","extra":` + nested + `}`
		start := time.Now()
		c, err := m.VerifyAccessToken(e.signRaw(t, payload))
		// Nested objects are unknown fields of the extra struct and are
		// skipped, so that spelling is a valid token. The other two cannot
		// decode into it and must be refused.
		if (c == nil) != (err != nil) || (name != "objects" && err == nil) {
			t.Errorf("%s: VerifyAccessToken = %+v, %v", name, c, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: took %v", name, d)
		}
	}
}

func split3(t testing.TB, token string) (h, p, s string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	return parts[0], parts[1], parts[2]
}

func tokenOfLength(t testing.TB, e *env, n int) string { return tokenOfLengthTyped(t, e, n, "access") }

// tokenOfLengthTyped signs a token whose compact form is exactly n bytes by
// growing an unused claim until the length lands. Base64 lengths of the form
// 4k+1 do not exist, so n must not be one.
func tokenOfLengthTyped(t testing.TB, e *env, n int, typ string) string {
	t.Helper()
	for pad := 0; pad < n; pad++ {
		tok := e.signEdDSA(t, nil, with(claimsFor(typ), "pad", strings.Repeat("a", pad)))
		switch {
		case len(tok) == n:
			return tok
		case len(tok) > n:
			t.Fatalf("no token of length %d: pad %d already gives %d", n, pad, len(tok))
		}
		// Jump close to the target to keep the search short.
		if gap := n - len(tok); gap > 8 {
			pad += gap*3/4 - 4
		}
	}
	t.Fatalf("no token of length %d", n)
	return ""
}
