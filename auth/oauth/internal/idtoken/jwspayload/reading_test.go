package jwspayload_test

import (
	"encoding/base64"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/idtoken/jwspayload"
)

func TestPayloadRejectsAmbiguousMembers(t *testing.T) {
	for _, raw := range []string{`{"sub":"a","sub":"b"}`, `{"sub":"a","SUB":"b"}`, `{"sub":"a","\u0073ub":"b"}`, `{"nested":{"id":1,"id":2}}`} {
		token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(raw)) + ".sig"
		if err := jwspayload.CheckText(token); err == nil {
			t.Errorf("accepted payload %s", raw)
		}
	}
}
