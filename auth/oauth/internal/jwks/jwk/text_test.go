package jwk_test

import (
	"fmt"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth/internal/jwks/jwk"
)

func TestDecodeRejectsRepairedKeyIdentifiers(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"kid", "issuer"} {
		for _, value := range []string{`"\ud800"`, `"\udfff"`, `"\ud800x"`, "\"\xff\"", "\"\xc3\""} {
			t.Run(fmt.Sprintf("%s/%q", name, value), func(t *testing.T) {
				raw := []byte(`{"kty":"RSA","` + name + `":` + value + `}`)
				if k, err := jwk.Decode(raw); err == nil {
					t.Fatalf("repaired identifier accepted: %+v", k)
				}
			})
		}
	}
}

func TestDecodePreservesValidUnicodeKeyIdentifiers(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"kid", "issuer"} {
		for _, tc := range []struct{ raw, want string }{{`"\ufffd"`, "�"}, {`"�"`, "�"}, {`"\ud83d\ude00"`, "😀"}, {`"clave-ñ"`, "clave-ñ"}, {`"\\ud800"`, `\ud800`}} {
			k, err := jwk.Decode([]byte(`{"kty":"RSA","` + name + `":` + tc.raw + `}`))
			if err != nil {
				t.Fatal(err)
			}
			got := k.Kid
			if name == "issuer" {
				got = k.Issuer
			}
			if got != tc.want {
				t.Errorf("%s = %q, want %q", name, got, tc.want)
			}
		}
	}
}
