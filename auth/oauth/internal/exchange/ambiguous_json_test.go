package exchange

import (
	"errors"
	"runtime"
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

// Members the client does not read keep their own spelling: two extension
// members that differ only in case are two members, as they are for a map, and
// a response that carries them is a valid one.
func TestDecodeAcceptsExtensionMembersThatDifferOnlyInCase(t *testing.T) {
	for _, body := range []string{
		`{"access_token":"a","token_type":"Bearer","ext":{"A":1,"a":2}}`,
		`{"access_token":"a","token_type":"Bearer","Scope":"x","scope":"y"}`,
	} {
		got, err := decode(params(), []byte(body), "secret", "code", "verifier")
		if err != nil || got == nil || got.AccessToken != "a" {
			t.Errorf("body %s: tokens=%v err=%v", body, got, err)
		}
	}
}

// A wide response of small sibling objects must not cost a name table each:
// the scan reused tables by depth, so what it allocates stays a small multiple
// of the body (a table per object made 800 KB cost 43 MB).
func TestDecodeCostOfManySiblingObjectsStaysBounded(t *testing.T) {
	body := `{"access_token":"a","token_type":"Bearer","ext":[` + strings.Repeat(`{"x":0},`, 100_000) + `{"x":0}]}`
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := decode(params(), []byte(body), "secret", "code", "verifier"); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if used := after.TotalAlloc - before.TotalAlloc; used > uint64(len(body))*8 {
		t.Fatalf("a %d byte response allocated %d bytes", len(body), used)
	}
}
