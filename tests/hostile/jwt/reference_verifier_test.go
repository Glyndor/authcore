package jwt_test

// An independent JWS verifier, written from RFC 7515 and RFC 8037 with only the
// standard library, so that "the module agrees with another implementation" is
// a statement about two code bases and not about one library calling itself.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var uuidV7 = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// refPolicy is what the reference verifier enforces.
type refPolicy struct {
	issuer   string
	audience string
	typ      string
	kid      string
	pub      ed25519.PublicKey
	now      time.Time
}

// refVerify returns nil when token is acceptable under p, and an error naming
// the first rule it breaks.
func refVerify(token string, p refPolicy) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not three segments")
	}
	dec := base64.RawURLEncoding.Strict()
	head, err := dec.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("header encoding: %w", err)
	}
	body, err := dec.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("payload encoding: %w", err)
	}
	sig, err := dec.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("signature encoding: %w", err)
	}

	var h map[string]any
	if err := json.Unmarshal(head, &h); err != nil {
		return fmt.Errorf("header json: %w", err)
	}
	if h["alg"] != "EdDSA" {
		return fmt.Errorf("alg %v", h["alg"])
	}
	if h["kid"] != p.kid {
		return fmt.Errorf("kid %v", h["kid"])
	}
	if !ed25519.Verify(p.pub, []byte(parts[0]+"."+parts[1]), sig) {
		return errors.New("signature")
	}

	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var c map[string]any
	if err := d.Decode(&c); err != nil {
		return fmt.Errorf("claims json: %w", err)
	}
	return refClaims(c, p)
}

// refClaims applies the claim rules to an already authenticated payload.
func refClaims(c map[string]any, p refPolicy) error {
	if c["iss"] != p.issuer {
		return fmt.Errorf("iss %v", c["iss"])
	}
	if !audienceHas(c["aud"], p.audience) {
		return fmt.Errorf("aud %v", c["aud"])
	}
	for _, name := range []string{"sub", "jti"} {
		s, _ := c[name].(string)
		if !uuidV7.MatchString(s) {
			return fmt.Errorf("%s %v is not a UUID v7", name, c[name])
		}
	}
	if c["type"] != p.typ {
		return fmt.Errorf("type %v", c["type"])
	}
	exp, ok := numericDate(c["exp"])
	if !ok {
		return fmt.Errorf("exp %v", c["exp"])
	}
	if !p.now.Before(exp) {
		return errors.New("expired")
	}
	for _, name := range []string{"iat", "nbf"} {
		raw, present := c[name]
		if !present {
			continue
		}
		v, ok := numericDate(raw)
		if !ok {
			return fmt.Errorf("%s %v", name, raw)
		}
		if v.After(p.now) {
			return fmt.Errorf("%s is in the future", name)
		}
	}
	return nil
}

func audienceHas(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		found := false
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return false // a non-string entry makes the whole claim malformed
			}
			found = found || s == want
		}
		return found
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 253402300799 {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)), true
}
