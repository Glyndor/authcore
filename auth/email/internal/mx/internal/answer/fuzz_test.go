package answer_test

import (
	"net"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/email/internal/mx/internal/answer"
)

// fuzzRecords splits the answer of the fuzzer into the records it holds:
// every newline ends one. An empty answer holds no record at all, and a
// lone newline holds one record with no host.
func fuzzRecords(raw string) []string {
	var records []string
	for {
		i := strings.IndexByte(raw, '\n')
		if i < 0 {
			return records
		}
		records = append(records, raw[:i])
		raw = raw[i+1:]
	}
}

// fuzzHasRealMX is the rule of RFC 7505 section 3 as this package applies
// it: the null MX is the one record that names no exchanger, and it refuses
// the answer only when it is the one record in it. A record that carries no
// host at all names no exchanger either, so an answer that holds nothing
// else means no mail.
//
// An answer of more than one record is taken as naming an exchanger, which is
// the rule the package's own test pins; this oracle claims no more than
// that.
func fuzzHasRealMX(hosts []string, nilRecord bool) bool {
	records := len(hosts)
	if nilRecord {
		records++
	}
	switch records {
	case 0:
		return false
	case 1:
		if nilRecord {
			return false
		}
		return hosts[0] != "." && hosts[0] != ""
	default:
		return true
	}
}

// FuzzHasRealMX drives the reading of a DNS MX answer with arbitrary records.
//
// The resolver is injectable, so a record that carries no host at all is
// representable, and the reading of the answer must not fall over on it. The
// rule: an answer that names no exchanger means no mail, and so does the
// single null MX record.
func FuzzHasRealMX(f *testing.F) {
	f.Add(".\n", false)
	f.Add("\n", false)
	f.Add("mail.example.com.\n", false)
	f.Add("mail.example.com.\n", true)
	f.Add(".\nmail.example.com.\n", false)
	f.Add("mail.example.com.\n.\n", false)
	f.Add(".\n", true)
	f.Add("", false)
	f.Add("", true)
	f.Add("a\nb\nc\n", false)

	f.Fuzz(func(t *testing.T, raw string, nilRecord bool) {
		if len(raw) > 1<<12 {
			// An answer of thousands of records is not what the contract is
			// about, and building one costs more than the check.
			t.Skip()
		}
		hosts := fuzzRecords(raw)
		mxs := make([]*net.MX, 0, len(hosts)+1)
		if nilRecord {
			mxs = append(mxs, nil)
		}
		for _, h := range hosts {
			mxs = append(mxs, &net.MX{Host: h, Pref: 10})
		}

		got := answer.HasRealMX(mxs)
		want := fuzzHasRealMX(hosts, nilRecord)
		if got != want {
			t.Fatalf("HasRealMX(%v) = %v, want %v", mxs, got, want)
		}
	})
}
