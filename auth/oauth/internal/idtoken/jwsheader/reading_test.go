package jwsheader_test

import (
	"encoding/base64"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken/jwsheader"
)

func TestHeaderRejectsAmbiguityAndRepairedText(t *testing.T) {
	for _, raw := range []string{
		`{"alg":"RS256","alg":"RS256"}`, `{"kid":"k1","KID":"k1"}`, `{"kid":"k1","\u006bid":"k1"}`,
		"{\"kid\":\"k\xff\"}", `{"kid":"k\ud800"}`, `{"kid":"k\udc00"}`,
	} {
		token := base64.RawURLEncoding.EncodeToString([]byte(raw)) + ".e30.sig"
		if err := jwsheader.RejectCritical(token); err == nil {
			t.Errorf("accepted header %q", raw)
		}
	}
	for _, raw := range []string{`{"alg":"RS256","kid":"k�"}`, `{"kid":"k\ud83d\ude00"}`, `{"kid":"k1","extra":{"kid":"k2"}}`} {
		token := base64.RawURLEncoding.EncodeToString([]byte(raw)) + ".e30.sig"
		if err := jwsheader.RejectCritical(token); err != nil {
			t.Errorf("legitimate header %s: %v", raw, err)
		}
	}
}
