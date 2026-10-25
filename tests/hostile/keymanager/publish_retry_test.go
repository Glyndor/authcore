//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// A refusal during the first publish must not be undone by starting again.
func TestHostile_RefusedPublishStaysRefusedOnRetry(t *testing.T) {
	bothModes(t, func(t *testing.T, loadOnly bool) {
		sb := newSandbox(t)
		dir := sb.keysDir(t)
		planted := newSet(t).secretHex
		path := filepath.Join(dir, layout.FileRefreshSecret)
		setFault(t, func(point string) error {
			if point == "published-public" {
				return os.WriteFile(path, planted, 0o600)
			}
			return nil
		})
		refused(t, open(t, dir, false))
		setFault(t, func(string) error { return nil })

		r := open(t, dir, loadOnly)

		if r.err == nil {
			t.Errorf("the retry loaded the secret written during the refused start (key id %s)", r.keys.KeyID())
		}
	})
}
