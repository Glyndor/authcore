package responses_test

import (
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

// A userinfo answer is one JSON value; anything after it, brackets included, is
// a malformed answer.
func TestHostile_UserInfo_nothingMayFollowTheValue(t *testing.T) {
	for _, body := range []string{`{"id":"1"}}`, `{"id":"1"}]`, `{"id":"1"}}}]]`, "{\"id\":\"1\"}\n}"} {
		srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte(body)))
		if info, err := hostiletest.UserinfoClient(t, srv.URL, nil).UserInfo(hostiletest.Ctx(t), "tok"); err == nil {
			t.Errorf("body %q accepted as %v", body, info)
		}
	}
	srv := hostiletest.Serve(t, hostiletest.StaticBody([]byte("{\"id\":\"1\"}\n ")))
	if _, err := hostiletest.UserinfoClient(t, srv.URL, nil).UserInfo(hostiletest.Ctx(t), "tok"); err != nil {
		t.Errorf("trailing whitespace must stay accepted: %v", err)
	}
}
