package apple

import (
	"bytes"
	"errors"
)

const (
	appleTestTeamID   = "ABCDE12345"
	appleTestKeyID    = "KEYID67890"
	appleTestClientID = "com.example.services"
)

// ErrInvalidConfig stands in for the public oauth.ErrInvalidConfig sentinel,
// which the oauth package passes to ClientSecret.
var ErrInvalidConfig = errors.New("oauth: invalid configuration")

// appleBase64Body returns the base64 body of the first PEM block in p8, or
// "" when p8 is not a PEM document. Used by tests to assert no 16-byte
// substring of the key material leaks through any error message.
func appleBase64Body(p8 []byte) string {
	for {
		i := bytes.Index(p8, []byte("-----BEGIN "))
		if i < 0 {
			return ""
		}
		end := bytes.Index(p8[i:], []byte("-----END "))
		if end < 0 {
			return ""
		}
		tail := p8[i+end:]
		fin := bytes.Index(tail, []byte("-----"))
		if fin < 0 {
			return ""
		}
		block := p8[i : i+end+fin+5]
		p8 = p8[i+end+fin+5:]
		eol := bytes.Index(block, []byte("\n"))
		if eol < 0 {
			continue
		}
		body := block[eol+1:]
		idx := bytes.Index(body, []byte("-----END "))
		if idx < 0 {
			continue
		}
		body = body[:idx]
		body = bytes.ReplaceAll(body, []byte("\n"), nil)
		body = bytes.ReplaceAll(body, []byte("\r"), nil)
		return string(body)
	}
}
