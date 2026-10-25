//go:build unix

package hostile

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Class 2: hostile file types and hostile contents where a key file goes.

// mkfifo creates a named pipe at path.
func mkfifo(t testing.TB, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// mksocket creates a unix socket node at path. The bind happens in a short
// directory because sun_path is limited to about 108 bytes, then the node is
// renamed into place.
func mksocket(t testing.TB, path string) {
	t.Helper()
	short, err := os.MkdirTemp("", "hs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(short, "s"))
	if err != nil {
		t.Skipf("cannot bind a unix socket here: %v", err)
	}
	// Closing the listener unlinks the node, so keep it open until cleanup.
	t.Cleanup(func() { _ = l.Close() })
	if err := os.Rename(filepath.Join(short, "s"), path); err != nil {
		t.Fatal(err)
	}
}

// mutation replaces the file at path with something hostile.
type mutation struct {
	name  string
	apply func(t *testing.T, sb sandbox, path string, original []byte)
}

func replaceWith(data []byte) func(*testing.T, sandbox, string, []byte) {
	return func(t *testing.T, _ sandbox, path string, _ []byte) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		put(t, path, data, 0o600)
	}
}

func replaceWithNode(make func(testing.TB, string)) func(*testing.T, sandbox, string, []byte) {
	return func(t *testing.T, _ sandbox, path string, _ []byte) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		make(t, path)
	}
}

func replaceWithLink(target string) func(*testing.T, sandbox, string, []byte) {
	return func(t *testing.T, _ sandbox, path string, _ []byte) {
		if _, err := os.Stat(target); err != nil {
			t.Skipf("%s does not exist here", target)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		mustSymlink(t, target, path)
	}
}

func mutations() []mutation {
	return []mutation{
		{"fifo", replaceWithNode(mkfifo)},
		{"unix socket", replaceWithNode(mksocket)},
		{"directory", func(t *testing.T, _ sandbox, path string, _ []byte) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			mustMkdir(t, path)
			put(t, filepath.Join(path, "inner"), []byte("x"), 0o600)
		}},
		{"link to /dev/null", replaceWithLink("/dev/null")},
		{"link to /dev/zero", replaceWithLink("/dev/zero")},
		{"link to /dev/urandom", replaceWithLink("/dev/urandom")},
		{"empty", replaceWith(nil)},
		{"only whitespace", replaceWith([]byte(" \n\t\r\n "))},
		{"truncated to half", func(t *testing.T, _ sandbox, path string, original []byte) {
			put(t, path, original[:len(original)/2], 0o600)
		}},
		{"truncated to one byte", func(t *testing.T, _ sandbox, path string, original []byte) {
			put(t, path, original[:1], 0o600)
		}},
		{"NUL bytes", replaceWith(bytes.Repeat([]byte{0}, 120))},
		{"NUL inside", func(t *testing.T, _ sandbox, path string, original []byte) {
			put(t, path, append(append([]byte{}, original[:20]...), append([]byte{0}, original[20:]...)...), 0o600)
		}},
		{"NUL appended", func(t *testing.T, _ sandbox, path string, original []byte) {
			put(t, path, append(append([]byte{}, original...), 0), 0o600)
		}},
		{"invalid UTF-8", func(t *testing.T, _ sandbox, path string, original []byte) {
			put(t, path, append(append([]byte{}, original[:25]...), append([]byte{0xff, 0xfe, 0xc0, 0x80}, original[25:]...)...), 0o600)
		}},
		{"UTF-8 BOM first", func(t *testing.T, _ sandbox, path string, original []byte) {
			put(t, path, append([]byte{0xef, 0xbb, 0xbf}, original...), 0o600)
		}},
		{"one byte over the cap", replaceWith(bytes.Repeat([]byte{'A'}, layout.MaxKeyFileSize+1))},
		{"1 MiB of text", replaceWith(bytes.Repeat([]byte("A"), 1<<20))},
		{"256 MiB sparse file", func(t *testing.T, _ sandbox, path string, _ []byte) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err := f.Truncate(256 << 20); err != nil {
				t.Skipf("filesystem cannot make a sparse file: %v", err)
			}
		}},
		{"valid PEM then one megabyte of text", func(t *testing.T, _ sandbox, path string, original []byte) {
			put(t, path, append(append([]byte{}, original...), bytes.Repeat([]byte("B"), 1<<20)...), 0o600)
		}},
	}
}

// keyTree snapshots dir without the files authcore may legitimately add on a
// refused run.
func keyTree(t testing.TB, dir string) map[string]entry {
	t.Helper()
	m := tree(t, dir)
	delete(m, layout.FileGitignore)
	return m
}

func TestHostile_FileTypes_hostileKeyFileIsRefusedAndNeverOverwritten(t *testing.T) {
	for _, name := range layout.KeyFileNames() {
		for _, m := range mutations() {
			t.Run(name+"/"+m.name, func(t *testing.T) {
				bothModes(t, func(t *testing.T, loadOnly bool) {
					sb := newSandbox(t)
					s := newSet(t)
					dir := sb.withSet(t, s)
					path := filepath.Join(dir, name)
					m.apply(t, sb, path, read(t, path))
					before := keyTree(t, dir)

					refused(t, open(t, dir, loadOnly), s)

					assertSame(t, "KeysDir", before, keyTree(t, dir))
				})
			})
		}
	}
}

func TestHostile_FileTypes_hugeFileIsNotReadIntoMemory(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.withSet(t, s)
	path := filepath.Join(dir, layout.FilePrivateKey)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 30); err != nil {
		_ = f.Close()
		t.Skipf("filesystem cannot make a 1 GiB sparse file: %v", err)
	}
	_ = f.Close()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	r := open(t, dir, true)
	runtime.ReadMemStats(&after)

	refused(t, r, s)
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 32<<20 {
		t.Errorf("a 1 GiB key file made the loader allocate %d MiB; the 4 KiB cap was not applied before reading", grown>>20)
	}
}

func TestHostile_FileTypes_capBoundaryIsExact(t *testing.T) {
	pad := func(data []byte, size int, fill byte) []byte {
		return append(append([]byte{}, data...), bytes.Repeat([]byte{fill}, size-len(data))...)
	}
	cases := []struct {
		name  string
		file  string
		build func(s keySet, size int) []byte
	}{
		{"private", layout.FilePrivateKey, func(s keySet, size int) []byte { return pad(s.privPEM, size, '\n') }},
		{"public", layout.FilePublicKey, func(s keySet, size int) []byte { return pad(s.pubPEM, size, '\n') }},
		{"secret", layout.FileRefreshSecret, func(s keySet, size int) []byte { return pad(s.secretHex, size, ' ') }},
	}
	for _, c := range cases {
		t.Run(c.name+"/exactly the cap", func(t *testing.T) {
			sb := newSandbox(t)
			s := newSet(t)
			dir := sb.withSet(t, s)
			put(t, filepath.Join(dir, c.file), c.build(s, layout.MaxKeyFileSize), 0o600)
			loaded(t, open(t, dir, true), s)
		})
		t.Run(c.name+"/one byte over", func(t *testing.T) {
			sb := newSandbox(t)
			s := newSet(t)
			dir := sb.withSet(t, s)
			put(t, filepath.Join(dir, c.file), c.build(s, layout.MaxKeyFileSize+1), 0o600)
			refused(t, open(t, dir, true), s)
		})
	}
}

func TestHostile_FileTypes_refreshSecretShapes(t *testing.T) {
	good := "9f2c7a41d83be5106ac9347fe20b6d58c14a97e3b05d28f6710ec4a93b8d5f26"
	cases := []struct {
		name    string
		content string
		ok      bool
	}{
		{"lowercase hex", good + "\n", true},
		{"uppercase hex", strings.ToUpper(good), true},
		{"CRLF", good + "\r\n", true},
		{"surrounding spaces", "  " + good + "\n\n", true},
		{"31 bytes", strings.Repeat("ab", 31), false},
		{"33 bytes", strings.Repeat("ab", 33), false},
		{"64 bytes", strings.Repeat("ab", 64), false},
		{"1 byte", "ab", false},
		{"empty", "", false},
		{"odd digit count", good[:63], false},
		{"0x prefix", "0x" + good, false},
		{"quoted", `"` + good + `"`, false},
		{"non-hex letter", good[:63] + "g", false},
		{"two lines", good + "\n" + good, false},
		{"embedded newline", good[:32] + "\n" + good[32:], false},
		{"embedded space", good[:32] + " " + good[32:], false},
		{"NUL after", good + "\x00", false},
		{"BOM first", "\ufeff" + good, false},
		{"32 raw bytes", strings.Repeat("\x01", 32), false},
		{"base64 of 32 bytes", "q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				sb := newSandbox(t)
				s := newSet(t)
				dir := sb.withSet(t, s)
				put(t, filepath.Join(dir, layout.FileRefreshSecret), []byte(c.content), 0o600)
				r := open(t, dir, loadOnly)
				if !c.ok {
					refused(t, r, s)
					return
				}
				if r.err != nil {
					t.Fatalf("expected a valid secret to load: %v", r.err)
				}
				if len(r.keys.RefreshSecret()) != layout.RefreshSecretLen {
					t.Fatalf("loaded a %d byte secret", len(r.keys.RefreshSecret()))
				}
			})
		})
	}
}

func TestHostile_FileTypes_keysDirOfTheWrongType(t *testing.T) {
	kinds := map[string]func(t *testing.T, path string){
		"regular file": func(t *testing.T, p string) { put(t, p, []byte("not a directory"), 0o600) },
		"fifo":         func(t *testing.T, p string) { mkfifo(t, p) },
		"socket":       func(t *testing.T, p string) { mksocket(t, p) },
		"link to file": func(t *testing.T, p string) {
			target := p + ".target"
			put(t, target, []byte("x"), 0o600)
			mustSymlink(t, target, p)
		},
		"link to /dev/null": func(t *testing.T, p string) { mustSymlink(t, "/dev/null", p) },
	}
	for name, mk := range kinds {
		t.Run(name, func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				sb := newSandbox(t)
				mk(t, sb.keys)
				before := tree(t, sb.root)

				refused(t, open(t, sb.keys, loadOnly))

				assertSame(t, "sandbox", before, tree(t, sb.root))
			})
		})
	}
}

func TestHostile_FileTypes_gitignoreOfAnyTypeDoesNotBlockOrBreakGeneration(t *testing.T) {
	kinds := map[string]func(t *testing.T, path string){
		"fifo":      func(t *testing.T, p string) { mkfifo(t, p) },
		"socket":    func(t *testing.T, p string) { mksocket(t, p) },
		"directory": func(t *testing.T, p string) { mustMkdir(t, p) },
		"dev null":  func(t *testing.T, p string) { mustSymlink(t, "/dev/null", p) },
	}
	for name, mk := range kinds {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			dir := sb.keysDir(t)
			mk(t, filepath.Join(dir, layout.FileGitignore))
			r := open(t, dir, false)
			if r.err != nil {
				t.Fatalf("a hostile .gitignore must not stop generation: %v", r.err)
			}
			for _, n := range layout.KeyFileNames() {
				if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
					t.Errorf("%s was not generated: %v", n, err)
				}
			}
		})
	}
}
