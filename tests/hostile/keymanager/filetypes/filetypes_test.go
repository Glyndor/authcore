//go:build unix

// Package filetypes attacks the key store with hostile file types and contents
// where a key file goes: pipes, sockets, huge files and malformed shapes.
package filetypes

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 2: hostile file types and hostile contents where a key file goes.

// mutation replaces the file at path with something hostile.
type mutation struct {
	name  string
	apply func(t *testing.T, sb hostiletest.Sandbox, path string, original []byte)
}

func replaceWith(data []byte) func(*testing.T, hostiletest.Sandbox, string, []byte) {
	return func(t *testing.T, _ hostiletest.Sandbox, path string, _ []byte) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		hostiletest.Put(t, path, data, 0o600)
	}
}

func replaceWithNode(make func(testing.TB, string)) func(*testing.T, hostiletest.Sandbox, string, []byte) {
	return func(t *testing.T, _ hostiletest.Sandbox, path string, _ []byte) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		make(t, path)
	}
}

func replaceWithLink(target string) func(*testing.T, hostiletest.Sandbox, string, []byte) {
	return func(t *testing.T, _ hostiletest.Sandbox, path string, _ []byte) {
		if _, err := os.Stat(target); err != nil {
			t.Skipf("%s does not exist here", target)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		hostiletest.MustSymlink(t, target, path)
	}
}

func mutations() []mutation {
	return []mutation{
		{"fifo", replaceWithNode(hostiletest.Mkfifo)},
		{"unix socket", replaceWithNode(hostiletest.Mksocket)},
		{"directory", func(t *testing.T, _ hostiletest.Sandbox, path string, _ []byte) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			hostiletest.MustMkdir(t, path)
			hostiletest.Put(t, filepath.Join(path, "inner"), []byte("x"), 0o600)
		}},
		{"link to /dev/null", replaceWithLink("/dev/null")},
		{"link to /dev/zero", replaceWithLink("/dev/zero")},
		{"link to /dev/urandom", replaceWithLink("/dev/urandom")},
		{"empty", replaceWith(nil)},
		{"only whitespace", replaceWith([]byte(" \n\t\r\n "))},
		{"truncated to half", func(t *testing.T, _ hostiletest.Sandbox, path string, original []byte) {
			hostiletest.Put(t, path, original[:len(original)/2], 0o600)
		}},
		{"truncated to one byte", func(t *testing.T, _ hostiletest.Sandbox, path string, original []byte) {
			hostiletest.Put(t, path, original[:1], 0o600)
		}},
		{"NUL bytes", replaceWith(bytes.Repeat([]byte{0}, 120))},
		{"NUL inside", func(t *testing.T, _ hostiletest.Sandbox, path string, original []byte) {
			hostiletest.Put(t, path, append(append([]byte{}, original[:20]...), append([]byte{0}, original[20:]...)...), 0o600)
		}},
		{"NUL appended", func(t *testing.T, _ hostiletest.Sandbox, path string, original []byte) {
			hostiletest.Put(t, path, append(append([]byte{}, original...), 0), 0o600)
		}},
		{"invalid UTF-8", func(t *testing.T, _ hostiletest.Sandbox, path string, original []byte) {
			hostiletest.Put(t, path, append(append([]byte{}, original[:25]...), append([]byte{0xff, 0xfe, 0xc0, 0x80}, original[25:]...)...), 0o600)
		}},
		{"UTF-8 BOM first", func(t *testing.T, _ hostiletest.Sandbox, path string, original []byte) {
			hostiletest.Put(t, path, append([]byte{0xef, 0xbb, 0xbf}, original...), 0o600)
		}},
		{"one byte over the cap", replaceWith(bytes.Repeat([]byte{'A'}, layout.MaxKeyFileSize+1))},
		{"1 MiB of text", replaceWith(bytes.Repeat([]byte("A"), 1<<20))},
		{"256 MiB sparse file", func(t *testing.T, _ hostiletest.Sandbox, path string, _ []byte) {
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
		{"valid PEM then one megabyte of text", func(t *testing.T, _ hostiletest.Sandbox, path string, original []byte) {
			hostiletest.Put(t, path, append(append([]byte{}, original...), bytes.Repeat([]byte("B"), 1<<20)...), 0o600)
		}},
	}
}

func TestHostile_FileTypes_hostileKeyFileIsRefusedAndNeverOverwritten(t *testing.T) {
	for _, name := range layout.KeyFileNames() {
		for _, m := range mutations() {
			t.Run(name+"/"+m.name, func(t *testing.T) {
				hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
					sb := hostiletest.NewSandbox(t)
					s := hostiletest.NewSet(t)
					dir := sb.WithSet(t, s)
					path := filepath.Join(dir, name)
					m.apply(t, sb, path, hostiletest.Read(t, path))
					before := hostiletest.KeyTree(t, dir)

					hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)

					hostiletest.AssertSame(t, "KeysDir", before, hostiletest.KeyTree(t, dir))
				})
			})
		}
	}
}

func TestHostile_FileTypes_hugeFileIsNotReadIntoMemory(t *testing.T) {
	sb := hostiletest.NewSandbox(t)
	s := hostiletest.NewSet(t)
	dir := sb.WithSet(t, s)
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
	r := hostiletest.Open(t, dir, true)
	runtime.ReadMemStats(&after)

	hostiletest.Refused(t, r, s)
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
		build func(s hostiletest.KeySet, size int) []byte
	}{
		{"private", layout.FilePrivateKey, func(s hostiletest.KeySet, size int) []byte { return pad(s.PrivPEM, size, '\n') }},
		{"public", layout.FilePublicKey, func(s hostiletest.KeySet, size int) []byte { return pad(s.PubPEM, size, '\n') }},
		{"secret", layout.FileRefreshSecret, func(s hostiletest.KeySet, size int) []byte { return pad(s.SecretHex, size, ' ') }},
	}
	for _, c := range cases {
		t.Run(c.name+"/exactly the cap", func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			s := hostiletest.NewSet(t)
			dir := sb.WithSet(t, s)
			hostiletest.Put(t, filepath.Join(dir, c.file), c.build(s, layout.MaxKeyFileSize), 0o600)
			hostiletest.Loaded(t, hostiletest.Open(t, dir, true), s)
		})
		t.Run(c.name+"/one byte over", func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			s := hostiletest.NewSet(t)
			dir := sb.WithSet(t, s)
			hostiletest.Put(t, filepath.Join(dir, c.file), c.build(s, layout.MaxKeyFileSize+1), 0o600)
			hostiletest.Refused(t, hostiletest.Open(t, dir, true), s)
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
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				sb := hostiletest.NewSandbox(t)
				s := hostiletest.NewSet(t)
				dir := sb.WithSet(t, s)
				hostiletest.Put(t, filepath.Join(dir, layout.FileRefreshSecret), []byte(c.content), 0o600)
				r := hostiletest.Open(t, dir, loadOnly)
				if !c.ok {
					hostiletest.Refused(t, r, s)
					return
				}
				if r.Err != nil {
					t.Fatalf("expected a valid secret to load: %v", r.Err)
				}
				if len(r.Keys.RefreshSecret()) != layout.RefreshSecretLen {
					t.Fatalf("loaded a %d byte secret", len(r.Keys.RefreshSecret()))
				}
			})
		})
	}
}

func TestHostile_FileTypes_keysDirOfTheWrongType(t *testing.T) {
	kinds := map[string]func(t *testing.T, path string){
		"regular file": func(t *testing.T, p string) { hostiletest.Put(t, p, []byte("not a directory"), 0o600) },
		"fifo":         func(t *testing.T, p string) { hostiletest.Mkfifo(t, p) },
		"socket":       func(t *testing.T, p string) { hostiletest.Mksocket(t, p) },
		"link to file": func(t *testing.T, p string) {
			target := p + ".target"
			hostiletest.Put(t, target, []byte("x"), 0o600)
			hostiletest.MustSymlink(t, target, p)
		},
		"link to /dev/null": func(t *testing.T, p string) { hostiletest.MustSymlink(t, "/dev/null", p) },
	}
	for name, mk := range kinds {
		t.Run(name, func(t *testing.T) {
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				sb := hostiletest.NewSandbox(t)
				mk(t, sb.Keys)
				before := hostiletest.Tree(t, sb.Root)

				hostiletest.Refused(t, hostiletest.Open(t, sb.Keys, loadOnly))

				hostiletest.AssertSame(t, "sandbox", before, hostiletest.Tree(t, sb.Root))
			})
		})
	}
}

func TestHostile_FileTypes_gitignoreOfAnyTypeDoesNotBlockOrBreakGeneration(t *testing.T) {
	kinds := map[string]func(t *testing.T, path string){
		"fifo":      func(t *testing.T, p string) { hostiletest.Mkfifo(t, p) },
		"socket":    func(t *testing.T, p string) { hostiletest.Mksocket(t, p) },
		"directory": func(t *testing.T, p string) { hostiletest.MustMkdir(t, p) },
		"dev null":  func(t *testing.T, p string) { hostiletest.MustSymlink(t, "/dev/null", p) },
	}
	for name, mk := range kinds {
		t.Run(name, func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			dir := sb.KeysDir(t)
			mk(t, filepath.Join(dir, layout.FileGitignore))
			r := hostiletest.Open(t, dir, false)
			if r.Err != nil {
				t.Fatalf("a hostile .gitignore must not stop generation: %v", r.Err)
			}
			for _, n := range layout.KeyFileNames() {
				if _, err := os.Lstat(filepath.Join(dir, n)); err != nil {
					t.Errorf("%s was not generated: %v", n, err)
				}
			}
		})
	}
}
