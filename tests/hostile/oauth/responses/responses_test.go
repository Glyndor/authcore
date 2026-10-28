package responses_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// Attacker: the other end of any of the four outbound fetches (token,
// userinfo, JWKS, discovery) when it is hostile, compromised or replaced by a
// man in the middle. Effect they want: exhaust the client's memory or time,
func TestHostile_Response_malformedOrWrongShapeNeverCountsAsSuccess(t *testing.T) {
	transform := func(f func(good []byte) []byte) func(*testing.T, surface, string) []byte {
		return func(t *testing.T, s surface, base string) []byte { return f(s.good(t, base)) }
	}
	attacks := map[string]reply{
		"truncated mid-document":             {body: transform(func(g []byte) []byte { return g[:len(g)/2] })},
		"truncated one byte short":           {body: transform(func(g []byte) []byte { return g[:len(g)-1] })},
		"trailing garbage":                   {body: transform(func(g []byte) []byte { return append(append([]byte(nil), g...), "garbage"...) })},
		"two documents back to back":         {body: transform(func(g []byte) []byte { return append(append([]byte(nil), g...), g...) })},
		"byte order mark":                    {body: transform(func(g []byte) []byte { return append([]byte("\xef\xbb\xbf"), g...) })},
		"NUL byte appended":                  {body: transform(func(g []byte) []byte { return append(append([]byte(nil), g...), 0) })},
		"html error page with status 200":    {headers: map[string]string{"Content-Type": "text/html"}, body: fixed("<html><body>Sign in</body></html>")},
		"empty body":                         {body: fixed("")},
		"whitespace only":                    {body: fixed(" \n\t ")},
		"top-level array":                    {body: fixed("[]")},
		"top-level array of the object":      {body: transform(func(g []byte) []byte { return append(append([]byte("["), g...), ']') })},
		"top-level null":                     {body: fixed("null")},
		"top-level string":                   {body: fixed(`"access_token"`)},
		"top-level number":                   {body: fixed("1")},
		"top-level bool":                     {body: fixed("true")},
		"empty object":                       {body: fixed("{}")},
		"valid body, status 500":             {status: 500},
		"valid body, status 404":             {status: 404},
		"valid body, status 401":             {status: 401},
		"valid body, status 403":             {status: 403},
		"valid body, status 429":             {status: 429},
		"valid body, status 301 no location": {status: 301},
		"valid body, status 304":             {status: 304},
		"valid body, status 204":             {status: 204},
		"valid body, status 400":             {status: 400},
		"one byte over the size cap": {body: func(t *testing.T, s surface, base string) []byte {
			return padJSON(s.good(t, base), hostiletest.ResponseCap+1)
		}},
		"gzip bomb": {headers: map[string]string{"Content-Encoding": "gzip"}, body: func(t *testing.T, s surface, base string) []byte {
			return gzipBomb(s.good(t, base))
		}},
		"gzip header over a plain body": {headers: map[string]string{"Content-Encoding": "gzip"}},
		"gzip stream cut off": {headers: map[string]string{"Content-Encoding": "gzip"}, body: func(t *testing.T, s surface, base string) []byte {
			return gzipBomb(nil)[:2048]
		}},
		"double gzip label": {headers: map[string]string{"Content-Encoding": "gzip, gzip"}, body: func(t *testing.T, s surface, base string) []byte {
			return gzipBomb(nil)
		}},
	}
	for _, s := range surfaces() {
		for name, r := range attacks {
			t.Run(s.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				var base string
				srv := hostiletest.Serve(t, r.handler(t, s, &base))
				base = srv.URL
				if err := s.call(t, base, nil); !errors.Is(err, s.refusal) {
					t.Fatalf("a hostile answer was not refused as %v: %v", s.refusal, err)
				}
			})
		}
	}
}

func TestHostile_Response_controlsTheCapIsExactAndWhitespaceIsFine(t *testing.T) {
	controls := map[string]reply{
		"plain valid answer": {},
		"exactly at the cap": {body: func(t *testing.T, s surface, base string) []byte {
			return padJSON(s.good(t, base), hostiletest.ResponseCap)
		}},
		"surrounding whitespace": {body: func(t *testing.T, s surface, base string) []byte {
			return append(append([]byte(" \n"), s.good(t, base)...), " \n"...)
		}},
		"gzip, as a normal server does": {headers: map[string]string{"Content-Encoding": "gzip"}, body: func(t *testing.T, s surface, base string) []byte {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(s.good(t, base))
			_ = zw.Close()
			return buf.Bytes()
		}},
	}
	for _, s := range surfaces() {
		for name, r := range controls {
			t.Run(s.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				var base string
				srv := hostiletest.Serve(t, r.handler(t, s, &base))
				base = srv.URL
				if err := s.call(t, base, nil); err != nil {
					t.Fatalf("control answer refused: %v", err)
				}
			})
		}
	}
}
