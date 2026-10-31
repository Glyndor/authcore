package credential

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/Glyndor/authcore/internal/clock"
)

func FuzzVerify(f *testing.F) {
	mod, err := New(fakeProvider{keys: fakeKeys{secret: []byte("0123456789abcdef0123456789abcdef")}})
	if err != nil {
		f.Fatalf("credential.New: %v", err)
	}
	mod.clock = clock.Fixed(epoch)

	enr, err := mod.Issue("reset", "alice@example.com")
	if err != nil {
		f.Fatalf("Issue: %v", err)
	}
	f.Add("reset", "alice@example.com", enr.Token, enr.Hash)
	f.Add("activate", "alice@example.com", enr.Token, enr.Hash)
	f.Add("reset", "bob@example.com", enr.Token, enr.Hash)
	f.Add("reset", "alice@example.com", "", "")
	f.Add("", "", "", "")
	f.Add("reset", "alice@example.com", "\x00\x00\x00", "deadbeef")
	f.Add("reset", "alice@example.com", enr.Token, enr.Hash[:60]) // truncated hash
	f.Add("reset", "alice@example.com", enr.Token, "")            // empty stored hash
	f.Add("reset", "alice@example.com", "short", enr.Hash)        // wrong token

	f.Fuzz(func(t *testing.T, purpose, subject, token, storedHash string) {
		mac := hmac.New(sha256.New, []byte("0123456789abcdef0123456789abcdef"))
		for _, value := range []string{purpose, subject, token} {
			frame := binary.BigEndian.AppendUint32(nil, uint32(len(value)))
			mac.Write(append(frame, value...))
		}
		want := storedHash == hex.EncodeToString(mac.Sum(nil))
		err := mod.Verify(purpose, subject, token, storedHash, epoch)
		if (err == nil) != want {
			t.Fatalf("Verify = %v, reference accept=%v", err, want)
		}
	})
}
