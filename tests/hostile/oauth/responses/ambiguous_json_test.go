package responses_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_ResponsesHaveOneReading(t *testing.T) {
	for _, operation := range []string{"exchange", "userinfo"} {
		fields := []string{"id", "sub", "error"}
		good := `"id":"alice","nested":{"id":"inside"},"items":[{"id":1},{"id":2}]`
		if operation == "exchange" {
			fields = []string{"access_token", "token_type", "refresh_token", "id_token", "expires_in", "error", "error_description"}
			good = `"access_token":"a","token_type":"Bearer","id_token":"x.y.z","nested":{"id":"inside"}`
		}
		for _, field := range fields {
			for _, alias := range []string{field, strings.ToUpper(field), escapeMember(field)} {
				for _, reverse := range []bool{false, true} {
					t.Run(operation+"/"+field+"/"+alias+map[bool]string{false: "/forward", true: "/reverse"}[reverse], func(t *testing.T) {
						first, second := `"`+field+`":"first"`, `"`+alias+`":"second"`
						if field == "expires_in" {
							first, second = `"`+field+`":1`, `"`+alias+`":2`
						}
						if reverse {
							first, second = second, first
						}
						// Keep one copy of the ordinary fields outside the pair being tested.
						base := good
						for _, member := range strings.Split(good, ",") {
							if strings.HasPrefix(member, `"`+field+`":`) {
								base = strings.Replace(base, member+",", "", 1)
							}
						}
						body := `{` + first + `,` + second + `,` + base + `}`
						runResponseReading(t, operation, body, false)
					})
				}
			}
		}
		t.Run(operation+"/legitimate", func(t *testing.T) { runResponseReading(t, operation, `{`+good+`}`, true) })
	}
}

func escapeMember(field string) string {
	const hex = "0123456789abcdef"
	return `\u00` + string(hex[field[0]>>4]) + string(hex[field[0]&15]) + field[1:]
}

func runResponseReading(t *testing.T, operation, body string, accept bool) {
	t.Helper()
	hc := &http.Client{Transport: hostiletest.RTFunc(func(r *http.Request) (*http.Response, error) {
		return hostiletest.MemResponse(r, 200, []byte(body)), nil
	})}
	var err error
	var absent bool
	sentinel := oauth.ErrExchange
	if operation == "exchange" {
		c := hostiletest.TokenClient(t, "https://idp.example/token", func(cfg *oauth.Config) { cfg.HTTPClient = hc })
		got, e := c.Exchange(hostiletest.Ctx(t), "code", "verifier")
		err, absent = e, got == nil
	} else {
		sentinel = oauth.ErrUserInfo
		c := hostiletest.UserinfoClient(t, "https://idp.example/userinfo", func(cfg *oauth.Config) { cfg.HTTPClient = hc })
		got, e := c.UserInfo(hostiletest.Ctx(t), "bearer")
		err, absent = e, got == nil
	}
	if accept {
		if err != nil || absent {
			t.Fatalf("legitimate response: absent=%v err=%v", absent, err)
		}
	} else if !absent || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "ambiguous member") {
		t.Fatalf("ambiguous response accepted: absent=%v err=%v", absent, err)
	}
}
