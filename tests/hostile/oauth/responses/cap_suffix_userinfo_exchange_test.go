package responses_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// A body that does not fit the cap is refused whole, never read as the prefix
// that does fit: a prefix that is valid on its own is a complete answer as far
// as the reader can tell, and the rest of the body would never be read at all.
func TestHostile_Response_CapRefusesThePrefixOfAnOversizedBody(t *testing.T) {
	for _, s := range surfaces() {
		var want error
		switch s.name {
		case "userinfo":
			want = oauth.ErrUserInfo
		case "exchange":
			want = oauth.ErrExchange
		default:
			continue
		}
		t.Run(s.name, func(t *testing.T) {
			base := "https://idp.example"
			good := s.good(t, base)
			if len(good) >= hostiletest.ResponseCap {
				t.Fatalf("fixture document exceeds cap")
			}
			// A body of exactly the cap bytes that is still a valid answer:
			// the prefix that fits is a whole document on its own.
			atCap := append(bytes.Clone(good), bytes.Repeat([]byte(" "), hostiletest.ResponseCap-len(good))...)
			if len(atCap) != hostiletest.ResponseCap {
				t.Fatalf("test fixture drifted: body is %d bytes, want %d", len(atCap), hostiletest.ResponseCap)
			}
			for _, tc := range []struct {
				name   string
				body   []byte
				accept bool
				// oversized marks a body that does not fit the cap, so the
				// refusal has to come from the size and not from the decoder.
				oversized bool
			}{
				{"under-cap-control", good, true, false},
				{"exact-cap-control", atCap, true, false},
				{"visible-junk-control", append(bytes.Clone(good), '!'), false, false},
				{"visible-document-control", append(bytes.Clone(good), []byte(`{}`)...), false, false},
				{"hidden-junk", append(bytes.Clone(atCap), '!'), false, true},
				{"hidden-document", append(bytes.Clone(atCap), []byte(`{}`)...), false, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					hits := 0
					read := &countingReader{r: bytes.NewReader(tc.body)}
					hc := &http.Client{Transport: hostiletest.RTFunc(func(r *http.Request) (*http.Response, error) {
						hits++
						return &http.Response{
							StatusCode:    http.StatusOK,
							Header:        http.Header{"Content-Type": {"application/json"}},
							Body:          io.NopCloser(read),
							ContentLength: -1, // the bound must hold without a length header
							Request:       r,
						}, nil
					})}
					err := s.call(t, base, hc)
					switch {
					case tc.accept && err != nil:
						t.Fatalf("a valid answer was refused: %v", err)
					case tc.accept:
					case !errors.Is(err, want):
						t.Fatalf("the oversized answer was not refused as %v: %v", want, err)
					default:
						if tc.oversized && !strings.Contains(err.Error(), fmt.Sprintf("%d bytes", hostiletest.ResponseCap)) {
							t.Errorf("the refusal does not name the cap: %v", err)
						}
					}
					if hits != 1 {
						t.Errorf("fixture requests = %d, want 1", hits)
					}
					if read.n > hostiletest.ResponseCap+1 {
						t.Errorf("the client read %d bytes, want at most %d", read.n, hostiletest.ResponseCap+1)
					}
				})
			}
		})
	}
}

// countingReader counts the bytes read from it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
