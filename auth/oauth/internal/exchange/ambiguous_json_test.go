package exchange

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeRefusesAmbiguousMembers(t *testing.T) {
	for _, body := range []string{
		`{"access_token":"a","access_token":"b","token_type":"Bearer"}`,
		`{"access_token":"a","ACCESS_TOKEN":"b","token_type":"Bearer"}`,
		`{"ACCESS_TOKEN":"a","token_type":"Bearer"}`,
		`{"access_token":"a","TOKEN_TYPE":"Bearer"}`,
		`{"access_token":"a","token_type":"Bearer","extra":{"id":1,"id":2}}`,
	} {
		got, err := decode(params(), []byte(body), "secret", "code", "verifier")
		if got != nil || !errors.Is(err, errExchange) || !strings.Contains(err.Error(), "ambiguous member") {
			t.Errorf("body %s: tokens=%v err=%v", body, got, err)
		}
	}
}
