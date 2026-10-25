package exchange

import (
	"context"
	"errors"
	"testing"
)

func TestDoRefusesABlankAccessTokenAndKeepsAPaddedOne(t *testing.T) {
	t.Parallel()
	for _, v := range []string{` `, `\t\n`, ` `} {
		body := `{"access_token":"` + v + `","token_type":"Bearer","id_token":"it"}`
		if _, err := Do(context.Background(), respond(200, body), params(), "c", "v"); !errors.Is(err, errExchange) {
			t.Errorf("access_token %q: err = %v", v, err)
		}
	}
	tok, err := Do(context.Background(), respond(200, `{"access_token":" at ","token_type":"Bearer","id_token":"it"}`), params(), "c", "v")
	if err != nil || tok.AccessToken != " at " {
		t.Fatalf("padded token: %+v, %v", tok, err)
	}
}
