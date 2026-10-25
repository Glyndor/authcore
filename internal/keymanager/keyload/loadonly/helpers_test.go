package loadonly_test

import (
	"os"
	"path/filepath"
	"testing"
)

// testLogger forwards what the key manager logs to the test log.
type testLogger struct{ t *testing.T }

func (l testLogger) Info(msg string, args ...any) { l.t.Logf("[INFO] "+msg, args...) }
func (l testLogger) Warn(msg string, args ...any) { l.t.Logf("[WARN] "+msg, args...) }

const metadataFile = "metadata.json"

// preMetadataDir builds a key directory in the layout that shipped before
// metadata.json existed: the three key files, no descriptor.
func preMetadataDir(t *testing.T) (dir string, keyID string) {
	t.Helper()
	dir = t.TempDir()
	km, err := New(dir, testLogger{t})
	if err != nil {
		t.Fatalf("seed New(): %v", err)
	}
	if err := os.Remove(filepath.Join(dir, metadataFile)); err != nil {
		t.Fatalf("strip %s: %v", metadataFile, err)
	}
	return dir, km.KeyID()
}
