package layout_test

import (
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// These values are part of what is on disk and of what a directory written by
// an earlier release is read with; a change is a format change.
func TestLayoutConstantsArePinned(t *testing.T) {
	if layout.DirMode != 0o700 {
		t.Errorf("DirMode = %04o, want 0700", layout.DirMode)
	}
	if layout.RefreshSecretLen != 32 {
		t.Errorf("RefreshSecretLen = %d, want 32", layout.RefreshSecretLen)
	}
	if layout.MaxKeyFileSize != 4096 {
		t.Errorf("MaxKeyFileSize = %d, want 4096", layout.MaxKeyFileSize)
	}
	if layout.StagingPrefix != ".staging-" {
		t.Errorf("StagingPrefix = %q", layout.StagingPrefix)
	}
}
