//go:build unix

package staging

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// A refusal during the first publish must not be undone by starting again.
func TestHostile_RefusedPublishStaysRefusedOnRetry(t *testing.T) {
	hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
		sb := hostiletest.NewSandbox(t)
		dir := sb.KeysDir(t)
		planted := hostiletest.NewSet(t).SecretHex
		path := filepath.Join(dir, layout.FileRefreshSecret)
		hostiletest.SetFault(t, func(point string) error {
			if point == "published-public" {
				return os.WriteFile(path, planted, 0o600)
			}
			return nil
		})
		hostiletest.Refused(t, hostiletest.Open(t, dir, false))
		hostiletest.SetFault(t, func(string) error { return nil })

		r := hostiletest.Open(t, dir, loadOnly)

		if r.Err == nil {
			t.Errorf("the retry loaded the secret written during the refused start (key id %s)", r.Keys.KeyID())
		}
	})
}
