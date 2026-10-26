package tokenshapes_test

import (
	"errors"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
	"github.com/Glyndor/authcore/tests/hostile/oauth/hostiletest"
)

func TestHostile_TokenResponse_blankAccessTokenIsRefused(t *testing.T) {
	for _, v := range []string{"   ", "\t", " \n ", " ", " "} {
		body := hostiletest.TokenBody(map[string]string{"access_token": v, "token_type": "Bearer", "id_token": "x"})
		if tok, err := exchangeBody(t, body, nil); !errors.Is(err, oauth.ErrExchange) {
			t.Errorf("access_token %q: got %+v, %v", v, tok, err)
		}
	}
	body := hostiletest.TokenBody(map[string]string{"access_token": " at ", "token_type": "Bearer", "id_token": "x"})
	tok, err := exchangeBody(t, body, nil)
	if err != nil || tok.AccessToken != " at " {
		t.Errorf("a padded token must come back untouched: %+v, %v", tok, err)
	}
}
