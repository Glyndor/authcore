package refusals

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Since auth/field shipped, "delete all key files" is the advice that destroys
// every encrypted column. No refusal may carry it.
func assertNoDestructiveAdvice(t *testing.T, err error) {
	t.Helper()
	for _, bad := range []string{"delete all key files", "delete both key files", "regenerate them"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("the refusal advises %q: %v", bad, err)
		}
	}
}

func TestTwoInits_namesTheFileAndTheDirectory(t *testing.T) {
	err := TwoInits("/keys", layout.FilePublicKey)
	for _, want := range []string{`"/keys"`, layout.FilePublicKey, "two different initialisations", "refusing to write or delete"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	assertNoDestructiveAdvice(t, err)
}

func TestInconsistent_listsPresentAndMissingAndForbidsDeletingTheSecret(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	err := Inconsistent(dir)
	for _, want := range []string{
		"present {" + layout.FilePrivateKey + "}",
		"missing {" + layout.FilePublicKey + ", " + layout.FileRefreshSecret + "}",
		"restore the missing file(s) from a backup",
		"refresh_secret.key must not be deleted or regenerated",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	assertNoDestructiveAdvice(t, err)
}

func TestRegeneration_recordsTheKeyIDAndNamesTheDeliberateEscape(t *testing.T) {
	err := Regeneration("/keys", "0123456789abcdef")
	for _, want := range []string{`"0123456789abcdef"`, "none of its files remain", "restore them from a backup", "delete metadata.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	assertNoDestructiveAdvice(t, err)
}

func TestWaitTimeout_namesWhatIsOnDiskAndNeverMentionsSymlinks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, layout.FilePrivateKey), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	err := WaitTimeout(dir)
	for _, want := range []string{"another initialiser started publishing", "present {" + layout.FilePrivateKey + "}", "a restart finishes it"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "symlink") {
		t.Errorf("the wait timeout must not talk about symlinks: %v", err)
	}
}

func TestWaitTimeout_emptyDirectoryReportsNone(t *testing.T) {
	err := WaitTimeout(t.TempDir())
	if !strings.Contains(err.Error(), "present {none}") {
		t.Errorf("an empty directory has nothing present: %v", err)
	}
}

func TestSymlinkTarget_wrapsTheCauseAndTellsHowToRecover(t *testing.T) {
	cause := errors.New("file exists")
	err := SymlinkTarget("/keys/ed25519_private.pem", cause)
	if !errors.Is(err, cause) {
		t.Error("the cause is not wrapped")
	}
	for _, want := range []string{"never writes key material through one", "remove it", "point KeysDir at the real directory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	assertNoDestructiveAdvice(t, err)
}

func TestNoHardLinks_mentionsKeptStagingOnlyWhenKept(t *testing.T) {
	cause := errors.New("operation not supported")
	kept := NoHardLinks("/keys", layout.FilePublicKey, true, cause)
	if !strings.Contains(kept.Error(), "staging directory has been kept as recovery material") {
		t.Errorf("a kept staging directory is not mentioned: %v", kept)
	}
	removed := NoHardLinks("/keys", layout.FilePublicKey, false, cause)
	if strings.Contains(removed.Error(), "kept as recovery material") {
		t.Errorf("a removed staging directory is reported as kept: %v", removed)
	}
	for _, err := range []error{kept, removed} {
		if !errors.Is(err, cause) || !strings.Contains(err.Error(), "Config.KeyStore") {
			t.Errorf("the refusal must wrap the cause and offer Config.KeyStore: %v", err)
		}
	}
}

func TestMissingDir_namesThePathAndTheThreeFiles(t *testing.T) {
	err := MissingDir("/keys")
	for _, want := range []string{`"/keys"`, layout.FilePrivateKey, layout.FilePublicKey, layout.FileRefreshSecret, "load-only mode"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
}

func TestIncompleteLoad_listsBothSidesAndSaysNoneWhenEmpty(t *testing.T) {
	err := IncompleteLoad("/keys", []string{layout.FilePrivateKey}, []string{layout.FilePublicKey, layout.FileRefreshSecret})
	for _, want := range []string{
		"present {" + layout.FilePrivateKey + "}",
		"missing {" + layout.FilePublicKey + ", " + layout.FileRefreshSecret + "}",
		"restore the missing file(s) from a backup",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in: %v", want, err)
		}
	}
	assertNoDestructiveAdvice(t, err)

	empty := IncompleteLoad("/keys", nil, layout.KeyFileNames())
	if !strings.Contains(empty.Error(), "present {none}") {
		t.Errorf("nothing present should read none: %v", empty)
	}
	full := IncompleteLoad("/keys", layout.KeyFileNames(), nil)
	if !strings.Contains(full.Error(), "missing {none}") {
		t.Errorf("nothing missing should read none: %v", full)
	}
}
