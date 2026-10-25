package linkkeys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/staging/stagingtest"
)

type warnLog struct{ warns []string }

func (*warnLog) Info(string, ...any) {}
func (l *warnLog) Warn(msg string, args ...any) {
	l.warns = append(l.warns, fmt.Sprintf(msg, args...))
}

// A loser that cannot remove its own staging directory says so.
func TestLink_reportsAStagingDirectoryItCouldNotRemove(t *testing.T) {
	stagingtest.PosixOnly(t)
	dir := t.TempDir()
	staging := filepath.Join(dir, layout.StagingPrefix+"loser")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range layout.KeyFileNames() {
		if err := os.WriteFile(filepath.Join(staging, name), []byte("mine"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(staging, "stray"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("winner"), 0600); err != nil {
		t.Fatal(err)
	}

	log := &warnLog{}
	if err := Link(dir, staging, log); !errors.Is(err, ErrWaitAndLoad) {
		t.Fatalf("Link = %v, want ErrWaitAndLoad", err)
	}
	if len(log.warns) != 1 || !strings.Contains(log.warns[0], "could not remove staging directory") {
		t.Fatalf("warnings = %q", log.warns)
	}
}
