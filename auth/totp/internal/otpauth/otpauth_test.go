package otpauth

import (
	"net/url"
	"testing"
)

func TestURI_withIssuer(t *testing.T) {
	got := URI("Acme Corp", "alice@example.com", "SECRET")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("URI = %q, want otpauth://totp/...", got)
	}
	// The label is the decoded path: issuer, one literal colon, account. Not
	// escaped a second time.
	if want := "/Acme Corp:alice@example.com"; u.Path != want {
		t.Errorf("label = %q, want %q", u.Path, want)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"secret": "SECRET", "issuer": "Acme Corp", "algorithm": "SHA1", "digits": "6", "period": "30",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
}

func TestURI_withoutIssuer(t *testing.T) {
	u, err := url.Parse(URI("", "alice", "SECRET"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/alice" {
		t.Errorf("label = %q, want /alice", u.Path)
	}
	if u.Query().Has("issuer") {
		t.Error("an empty issuer must not add an issuer parameter")
	}
}

// A colon inside the issuer or the account is escaped so the one literal
// colon stays the separator.
func TestURI_escapesColons(t *testing.T) {
	got := URI("A:B", "c:d", "S")
	const wantPrefix = "otpauth://totp/A%3AB:c%3Ad?"
	if len(got) < len(wantPrefix) || got[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("URI = %q, want prefix %q", got, wantPrefix)
	}
}
