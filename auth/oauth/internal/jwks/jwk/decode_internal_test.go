package jwk

import (
	"reflect"
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
