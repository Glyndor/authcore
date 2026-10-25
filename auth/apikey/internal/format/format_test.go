package format

import (
	"strings"
	"testing"
)

var (
	id     = strings.Repeat("ab", IDLen)
	secret = strings.Repeat("0f", SecretLen)
)

func TestJoin_thenParseIDRoundTrips(t *testing.T) {
	key := Join("ak", id, secret)
	if key != "ak_"+id+"_"+secret {
		t.Fatalf("Join = %q", key)
	}
	got, ok := ParseID("ak", key)
	if !ok || got != id {
		t.Errorf("ParseID = %q, %v; want %q, true", got, ok, id)
	}
}

func TestParseID_refusesAnythingButTheThreeFieldShape(t *testing.T) {
	cases := map[string]string{
		"empty":                "",
		"wrong prefix":         Join("sk", id, secret),
		"prefix only":          "ak_",
		"no secret":            "ak_" + id,
		"empty id":             "ak__" + secret,
		"short id":             Join("ak", id[:31], secret),
		"long id":              Join("ak", id+"a", secret),
		"short secret":         Join("ak", id, secret[:63]),
		"long secret":          Join("ak", id, secret+"a"),
		"extra trailing":       Join("ak", id, secret) + "_extra",
		"uppercase id":         Join("ak", strings.ToUpper(id), secret),
		"non-hex id":           Join("ak", strings.Repeat("g", 32), secret),
		"non-hex secret":       Join("ak", id, strings.Repeat("z", 64)),
		"prefix without sep":   "ak" + id + "_" + secret,
		"secret uppercase hex": Join("ak", id, strings.ToUpper(secret)),
	}
	for name, key := range cases {
		if got, ok := ParseID("ak", key); ok {
			t.Errorf("%s: ParseID(%q) = %q, true; want false", name, key, got)
		}
	}
}
