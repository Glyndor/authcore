package exchange

import (
	"context"
	"errors"
	"testing"
)

func TestDoBoundsExpiresIn(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]int{"0": 0, "60": 60, "315360000": expiresInMax, "315360001": expiresInMax, "9223372036854775807": expiresInMax} {
		body := `{"access_token":"at","token_type":"Bearer","id_token":"it","expires_in":` + raw + `}`
		tok, err := Do(context.Background(), respond(200, body), params(), "c", "v")
		if err != nil || tok.ExpiresIn != want {
			t.Errorf("expires_in %s: %+v, %v; want %d", raw, tok, err, want)
		}
	}
	body := `{"access_token":"at","token_type":"Bearer","id_token":"it","expires_in":-1}`
	if _, err := Do(context.Background(), respond(200, body), params(), "c", "v"); !errors.Is(err, errExchange) {
		t.Errorf("negative expires_in: err = %v", err)
	}
}
