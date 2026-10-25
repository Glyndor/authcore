package hostile_test

import "testing"

// A userinfo answer is one JSON value; anything after it, brackets included, is
// a malformed answer.
func TestHostile_UserInfo_nothingMayFollowTheValue(t *testing.T) {
	for _, body := range []string{`{"id":"1"}}`, `{"id":"1"}]`, `{"id":"1"}}}]]`, "{\"id\":\"1\"}\n}"} {
		srv := serve(t, staticBody([]byte(body)))
		if info, err := userinfoClient(t, srv.URL, nil).UserInfo(ctx(t), "tok"); err == nil {
			t.Errorf("body %q accepted as %v", body, info)
		}
	}
	srv := serve(t, staticBody([]byte("{\"id\":\"1\"}\n ")))
	if _, err := userinfoClient(t, srv.URL, nil).UserInfo(ctx(t), "tok"); err != nil {
		t.Errorf("trailing whitespace must stay accepted: %v", err)
	}
}
