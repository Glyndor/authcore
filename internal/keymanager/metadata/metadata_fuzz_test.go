package metadata

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// FuzzRead drives metadata.json parsing with arbitrary file contents. It must
// never panic; it must refuse anything over the read cap, anything that is not
// valid JSON and any format outside 1..CurrentFormat; and it must never
// report "no file" for a file that is there.
func FuzzRead(f *testing.F) {
	f.Add([]byte(`{"format":1,"created":"2020-01-01T00:00:00Z","key_id":"0123456789abcdef"}`))
	f.Add([]byte(`{"format":2}`))
	f.Add([]byte(`{"format":1,"format":99}`))
	f.Add([]byte(`{"format":99,"format":1}`))
	f.Add([]byte(`{"format":0}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[`))
	f.Add([]byte("{\"format\":1,\"key_id\":\"\xff\x00\"}"))
	f.Add([]byte{})
	f.Add(make([]byte, layout.MaxKeyFileSize+1))

	dir := f.TempDir()
	path := filepath.Join(dir, layout.FileMetadata)
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		m, err := Read(dir)
		if err != nil {
			if m != nil {
				t.Fatal("a value was returned alongside an error")
			}
			return
		}
		if m == nil {
			t.Fatalf("a file that exists was reported as absent: %q", data)
		}
		if len(data) > layout.MaxKeyFileSize {
			t.Fatalf("accepted a %d byte file, over the %d byte cap", len(data), layout.MaxKeyFileSize)
		}
		if !json.Valid(data) {
			t.Fatalf("accepted something that is not JSON: %q", data)
		}
		if m.Format < 1 || m.Format > CurrentFormat {
			t.Fatalf("accepted format %d", m.Format)
		}
	})
}
