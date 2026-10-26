package wait_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/recoverytest"
	"github.com/Glyndor/authcore/internal/keymanager/recovery/wait"
)

// A loser of the publish race keeps polling until the winner has finished; it
// does not give up at the first look.
func TestForSet_KeepsPollingUntilTheSetIsComplete(t *testing.T) {
	dir := recoverytest.MustSeed(t, t.TempDir())
	pub := filepath.Join(dir, layout.FilePublicKey)
	data, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pub); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		time.Sleep(80 * time.Millisecond)
		done <- os.WriteFile(pub, data, 0o644)
	}()

	if err := wait.ForSet(dir, recoverytest.SilentLog{}); err != nil {
		t.Fatalf("ForSet = %v, want success once the winner finished", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
