package hostile_test

import (
	"net/http"
	"testing"
)

// A same-origin 307 or 308 replays the request body. The token request must
// carry the client secret again on the replay, and only to the same origin.
func TestHostile_Token_sameOriginRedirectReplaysTheForm(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		src, _ := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				http.Redirect(w, r, "/token2", status)
				return
			}
			_ = r.ParseForm()
			if r.PostForm.Get("client_secret") == "" {
				http.Error(w, "secret missing on replay", 400)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"a","token_type":"Bearer","id_token":"x.y.z"}`))
		}))
		if err := endpoints()[0].run(t, named(src.URL), insecureClient()); err != nil {
			t.Errorf("status %d: a same-origin redirect on the token endpoint failed: %v", status, err)
		}
	}
}
