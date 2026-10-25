package keyissuer

import (
	"errors"
	"strings"
	"testing"

	gjwt "github.com/golang-jwt/jwt/v5"
)

var errInvalid = errors.New("oauth: id token is invalid")

func TestCheckKeyIssuer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		keyIssuer string
		claims    gjwt.MapClaims
		wantErr   string
	}{
		{"unrestricted key", "", gjwt.MapClaims{"iss": "anything"}, ""},
		{"pinned and equal", "https://p.example", gjwt.MapClaims{"iss": "https://p.example"}, ""},
		{"pinned and different", "https://p.example", gjwt.MapClaims{"iss": "https://q.example"}, "not the"},
		{"template completed by tid", "https://p.example/{tenantid}/v2.0", gjwt.MapClaims{"iss": "https://p.example/t1/v2.0", "tid": "t1"}, ""},
		{"template without tid", "https://p.example/{tenantid}/v2.0", gjwt.MapClaims{"iss": "https://p.example/t1/v2.0"}, "no tid"},
		{"template with mismatching tid", "https://p.example/{tenantid}/v2.0", gjwt.MapClaims{"iss": "https://p.example/t2/v2.0", "tid": "t1"}, "not the"},
	}
	for _, tc := range tests {
		err := Check(errInvalid, tc.keyIssuer, tc.claims)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.wantErr != "" && (!errors.Is(err, errInvalid) || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: err = %v, want %q wrapping errInvalid", tc.name, err, tc.wantErr)
		}
	}
}
