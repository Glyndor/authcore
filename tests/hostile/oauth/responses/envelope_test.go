package responses_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// A 200 that carries an OAuth error must not become a login.
func TestHostile_Response_errorEnvelopeWith200(t *testing.T) {
	t.Run("exchange", func(t *testing.T) {
		for name, body := range map[string]string{
			"plain error":               `{"error":"invalid_grant"}`,
			"error beside valid tokens": `{"error":"invalid_grant","access_token":"a","token_type":"Bearer","id_token":"i.i.i"}`,
			"error null beside tokens":  `{"error":null,"access_token":"a","token_type":"Bearer","id_token":"i.i.i"}`,
			"error number":              `{"error":400,"access_token":"a","token_type":"Bearer","id_token":"i.i.i"}`,
			"error with description":    `{"error":"invalid_client","error_description":"bad secret"}`,
			"error object":              `{"error":{"code":"x"},"access_token":"a","token_type":"Bearer","id_token":"i.i.i"}`,
			"no access token":           `{"token_type":"Bearer","id_token":"i.i.i"}`,
			"empty access token":        `{"access_token":"","token_type":"Bearer","id_token":"i.i.i"}`,
			"access token null":         `{"access_token":null,"token_type":"Bearer","id_token":"i.i.i"}`,
			"access token a number":     `{"access_token":7,"token_type":"Bearer","id_token":"i.i.i"}`,
			"access token an array":     `{"access_token":["a"],"token_type":"Bearer","id_token":"i.i.i"}`,
			"no token type":             `{"access_token":"a","id_token":"i.i.i"}`,
			"empty token type":          `{"access_token":"a","token_type":"","id_token":"i.i.i"}`,
			"expires_in a string":       `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","expires_in":"3600"}`,
			"expires_in a float":        `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","expires_in":3600.5}`,
			"expires_in enormous":       `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","expires_in":99999999999999999999}`,
			"expires_in infinite":       `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","expires_in":1e999}`,
			"id_token a number":         `{"access_token":"a","token_type":"Bearer","id_token":5}`,
			"id_token an object":        `{"access_token":"a","token_type":"Bearer","id_token":{"a":1}}`,
			"refresh_token an object":   `{"access_token":"a","token_type":"Bearer","id_token":"i.i.i","refresh_token":{}}`,
		} {
			t.Run(name, func(t *testing.T) {
				srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte(body)))
				c := hostiletest.TokenClient(t, srv.URL+"/token", nil)
				if tok, err := c.Exchange(hostiletest.Ctx(t), "code", "verifier"); !errors.Is(err, oauth.ErrExchange) {
					t.Fatalf("not refused as ErrExchange: %v (tokens %+v)", err, tok)
				}
			})
		}
	})
	t.Run("an OIDC exchange with no id_token is its own error", func(t *testing.T) {
		srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte(`{"access_token":"a","token_type":"Bearer"}`)))
		c := hostiletest.TokenClient(t, srv.URL+"/token", nil)
		if _, err := c.Exchange(hostiletest.Ctx(t), "code", "verifier"); !errors.Is(err, oauth.ErrNoIDToken) {
			t.Fatalf("want ErrNoIDToken, got %v", err)
		}
	})
	t.Run("userinfo", func(t *testing.T) {
		for name, body := range map[string]string{
			"error object":           `{"error":"invalid_token"}`,
			"error beside a profile": `{"error":"invalid_token","id":"42"}`,
			"empty object":           `{}`,
			"null":                   `null`,
			"array":                  `[{"id":"42"}]`,
			"trailing junk":          `{"id":"42"}garbage`,
			"second object":          `{"id":"42"}{"id":"43"}`,
		} {
			t.Run(name, func(t *testing.T) {
				srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte(body)))
				c := hostiletest.UserinfoClient(t, srv.URL, nil)
				if info, err := c.UserInfo(hostiletest.Ctx(t), "tok"); !errors.Is(err, oauth.ErrUserInfo) {
					t.Fatalf("not refused as ErrUserInfo: %v (profile %v)", err, info)
				}
			})
		}
	})
	t.Run("jwks", func(t *testing.T) {
		for name, body := range map[string]string{
			"error object":          `{"error":"server_error"}`,
			"empty set":             `{"keys":[]}`,
			"keys null":             `{"keys":null}`,
			"keys a string":         `{"keys":"x"}`,
			"keys an object":        `{"keys":{}}`,
			"keys of numbers":       `{"keys":[1,2]}`,
			"keys of nulls":         `{"keys":[null,null]}`,
			"keys of empty objects": `{"keys":[{},{}]}`,
			"top-level array":       `[]`,
		} {
			t.Run(name, func(t *testing.T) {
				c, _ := hostiletest.JWKSClient(t, []byte(body))
				got, err := hostiletest.Verify(t, c, hostiletest.SignA(t, hostiletest.Claims(hostiletest.Nonce, nil)))
				hostiletest.MustRejectToken(t, got, err)
			})
		}
	})
}

// Numbers that do not fit a float64 must survive a userinfo round trip exactly:
// an id that collapses onto its neighbour merges two accounts.
func TestHostile_Response_userinfoLargeNumbersStayExact(t *testing.T) {
	srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte(`{"id":9007199254740993,"big":1e999999,"neg":-9223372036854775809,"frac":0.1000000000000000055511151231257827}`)))
	c := hostiletest.UserinfoClient(t, srv.URL, nil)
	info, err := c.UserInfo(hostiletest.Ctx(t), "tok")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	for k, want := range map[string]string{"id": "9007199254740993", "big": "1e999999", "neg": "-9223372036854775809"} {
		n, ok := info[k].(json.Number)
		if !ok || n.String() != want {
			t.Errorf("%s = %#v, want json.Number %s", k, info[k], want)
		}
	}
}

func TestHostile_Response_deeplyNestedJSONIsRefusedWithoutBlowingTheStack(t *testing.T) {
	// 100k levels fit under the 1 MiB cap. The decoder must stop long before the stack does.
	nestedArray := strings.Repeat("[", 100000) + strings.Repeat("]", 100000)
	nestedObject := strings.Repeat(`{"a":`, 100000) + "1" + strings.Repeat("}", 100000)
	bodies := map[string]func(good string) string{
		"nested arrays as an unused member":  func(g string) string { return g[:len(g)-1] + `,"x":` + nestedArray + "}" },
		"nested objects as an unused member": func(g string) string { return g[:len(g)-1] + `,"x":` + nestedObject + "}" },
		"nested arrays at the root":          func(string) string { return nestedArray },
		"nested objects at the root":         func(string) string { return nestedObject },
	}
	for _, s := range surfaces() {
		for name, f := range bodies {
			t.Run(s.name+"/"+name, func(t *testing.T) {
				t.Parallel()
				var base string
				srv := hostiletest.Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write([]byte(f(string(s.good(t, base)))))
				}))
				base = srv.URL
				if err := s.call(t, base, nil); !errors.Is(err, s.refusal) {
					t.Fatalf("a document nested 100000 levels deep was not refused as %v: %v", s.refusal, err)
				}
			})
		}
	}
}
