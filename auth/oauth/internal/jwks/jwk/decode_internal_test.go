package jwk

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The members mirror exists to notice a member the document writes twice, so
// it must carry exactly the members of the JWK: one it does not carry is one
// whose ambiguity goes unnoticed.
func TestMembersMirrorTheJWK(t *testing.T) {
	t.Parallel()
	jwkType := reflect.TypeOf(JWK{})
	membersType := reflect.TypeOf(members{})
	if jwkType.NumField() != membersType.NumField() {
		t.Fatalf("the mirror carries %d members, the JWK %d", membersType.NumField(), jwkType.NumField())
	}
	for i := range jwkType.NumField() {
		want := jwkType.Field(i).Tag.Get("json")
		got := membersType.Field(i).Tag.Get("json")
		if want != got {
			t.Errorf("member %d: the mirror says %q, the JWK says %q", i, got, want)
		}
	}
}

func TestDecodeRejectsEveryRepeatedMember(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"kty", "kid", "use", "alg", "key_ops", "n", "e", "crv", "x", "y", "issuer"} {
		for _, spelling := range []string{name, strings.ToUpper(name), `\u00` + fmt.Sprintf("%02x", name[0]) + name[1:]} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/reverse=%v", name, spelling, reverse), func(t *testing.T) {
					a, b := `"first"`, `"second"`
					if name == "key_ops" {
						a, b = `["verify"]`, `["encrypt"]`
					}
					left, right := `"`+name+`":`+a, `"`+spelling+`":`+b
					if reverse {
						left, right = right, left
					}
					for _, single := range []string{left, right} {
						if _, err := Decode([]byte("{" + single + "}")); err != nil {
							t.Fatalf("unambiguous control rejected: %v", err)
						}
					}
					if _, err := Decode([]byte("{" + left + "," + right + "}")); err == nil || !strings.Contains(err.Error(), "more than once") {
						t.Fatalf("duplicate %s accepted or wrong refusal: %v", name, err)
					}
				})
			}
		}
	}
}
