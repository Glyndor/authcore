//go:build unix

// Package hostile attacks the on-disk key store from the outside. The
// adversary is another local user, a concurrent process, a holder of partial
// write access to KeysDir or a hostile mounted volume. Every test drives the
// public authcore API (authcore.New with Config.KeysDir) or the
// authcore-keygen binary, then checks the effects that must stay forbidden:
// reading or writing outside KeysDir, overwriting or leaking a key, ending
// with a half-written or mixed key set, loading another set's keys, and
// hiding corruption.
//
// The package is Unix only: it needs FIFOs, sockets, hard links, umask and
// mode bits, so a build constraint excludes it elsewhere instead of letting
// individual tests skip themselves silently.
//
// The only test-side hooks are the seams the key manager already exposes for
// its own tests (internal/keymanager/seams). They are process-global, so no
// test in this package runs in parallel.
package hostile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/keymanager/layout"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// recLog is an authcore.Logger that keeps every formatted message.
type recLog struct {
	mu    sync.Mutex
	lines []string
}

func (r *recLog) add(level, msg string, args []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, level+" "+fmt.Sprintf(msg, args...))
}

func (r *recLog) Debug(msg string, args ...any) { r.add("DEBUG", msg, args) }
func (r *recLog) Info(msg string, args ...any)  { r.add("INFO", msg, args) }
func (r *recLog) Warn(msg string, args ...any)  { r.add("WARN", msg, args) }
func (r *recLog) Error(msg string, args ...any) { r.add("ERROR", msg, args) }

// all returns every message joined, for leak and substring checks.
func (r *recLog) all() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.lines, "\n")
}

func (r *recLog) has(fragment string) bool { return strings.Contains(r.all(), fragment) }

// keySet is one complete, valid key set in memory.
type keySet struct {
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	secret    []byte
	privPEM   []byte
	pubPEM    []byte
	secretHex []byte
}

func newSet(t testing.TB) keySet {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, layout.RefreshSecretLen)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	privPEM, err := pemcodec.EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := pemcodec.EncodePublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	return keySet{priv, pub, secret, privPEM, pubPEM, append([]byte(hex.EncodeToString(secret)), '\n')}
}

// writeFiles lays the three key files into dir with the modes authcore uses.
func (s keySet) writeFiles(t testing.TB, dir string) {
	t.Helper()
	put(t, filepath.Join(dir, layout.FilePrivateKey), s.privPEM, 0o600)
	put(t, filepath.Join(dir, layout.FilePublicKey), s.pubPEM, 0o644)
	put(t, filepath.Join(dir, layout.FileRefreshSecret), s.secretHex, 0o600)
}

// keyID is the identifier authcore derives for the set.
func (s keySet) keyID() string {
	h := sha256.Sum256(s.pub)
	return hex.EncodeToString(h[:8])
}

// needles lists the encodings in which the private material could leak: hex,
// base64, the decimal byte slice %v prints and the Go-syntax hex %#v prints.
func (s keySet) needles() []string {
	body := func(b []byte) string {
		blk, _ := pem.Decode(b)
		return base64.StdEncoding.EncodeToString(blk.Bytes)
	}
	decimal := func(b []byte) string {
		parts := make([]string, 8)
		for i := range parts {
			parts[i] = fmt.Sprint(b[i])
		}
		return strings.Join(parts, " ")
	}
	goSyntax := func(b []byte) string {
		return fmt.Sprintf("0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x", b[0], b[1], b[2], b[3], b[4])
	}
	return []string{
		hex.EncodeToString(s.priv), hex.EncodeToString(s.priv.Seed()), hex.EncodeToString(s.secret),
		base64.StdEncoding.EncodeToString(s.priv), base64.StdEncoding.EncodeToString(s.priv.Seed()),
		base64.RawURLEncoding.EncodeToString(s.priv.Seed()), base64.StdEncoding.EncodeToString(s.secret),
		body(s.privPEM), decimal(s.priv.Seed()), decimal(s.secret), goSyntax(s.priv.Seed()), goSyntax(s.secret),
	}
}

// assertNoLeak fails when any text carries private material of any set given.
func assertNoLeak(t testing.TB, what string, sets []keySet, texts ...string) {
	t.Helper()
	for _, text := range texts {
		for _, s := range sets {
			for _, n := range s.needles() {
				if strings.Contains(text, n) {
					t.Errorf("%s leaks key material (%.12s...): %.200q", what, n, text)
				}
			}
		}
	}
}

func put(t testing.TB, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func read(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustMkdir(t testing.TB, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustSymlink(t testing.TB, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// result is what authcore.New reported.
type result struct {
	keys authcore.Keys
	log  *recLog
	err  error
}

// open runs authcore.New against dir under a deadline, so a hostile entry that
// makes the loader block is a failure rather than a hung suite.
func open(t testing.TB, dir string, loadOnly bool) result {
	t.Helper()
	log := &recLog{}
	done := make(chan result, 1)
	go func() {
		a, err := authcore.New(authcore.Config{KeysDir: dir, Logger: log, RequireExistingKeys: loadOnly})
		var keys authcore.Keys
		if a != nil {
			keys = a.Keys()
		}
		done <- result{keys, log, err}
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("authcore.New(%q, loadOnly=%v) did not return within 10s", dir, loadOnly)
		return result{}
	}
}

// bothModes runs fn once for the writable store and once for load-only.
func bothModes(t *testing.T, fn func(t *testing.T, loadOnly bool)) {
	t.Helper()
	t.Run("new", func(t *testing.T) { fn(t, false) })
	t.Run("load", func(t *testing.T) { fn(t, true) })
}

// entry is one node of a tree snapshot.
type entry string

// tree snapshots root without following links: path to kind, mode and content
// hash, or the link target. Two equal snapshots mean nothing changed.
func tree(t testing.TB, root string) map[string]entry {
	t.Helper()
	out := map[string]entry{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			dst, _ := os.Readlink(p)
			out[rel] = entry("link->" + dst)
		case fi.IsDir():
			out[rel] = entry(fmt.Sprintf("dir %04o", fi.Mode().Perm()))
		case fi.Mode().IsRegular() && fi.Size() > 1<<20:
			// Too big to hash cheaply; the size and mode still catch a rewrite.
			out[rel] = entry(fmt.Sprintf("big file %04o %d", fi.Mode().Perm(), fi.Size()))
		case fi.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				out[rel] = entry(fmt.Sprintf("unreadable %04o", fi.Mode().Perm()))
				return nil
			}
			sum := sha256.Sum256(data)
			out[rel] = entry(fmt.Sprintf("file %04o %x", fi.Mode().Perm(), sum[:6]))
		default:
			out[rel] = entry("special " + fi.Mode().Type().String())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// assertSame fails when the tree under root differs from before.
func assertSame(t testing.TB, what string, before, after map[string]entry) {
	t.Helper()
	for p, e := range before {
		if got, ok := after[p]; !ok {
			t.Errorf("%s: %q was removed (was %s)", what, p, e)
		} else if got != e {
			t.Errorf("%s: %q changed from %s to %s", what, p, e, got)
		}
	}
	for p, e := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("%s: %q appeared (%s)", what, p, e)
		}
	}
}

// stagingDirs lists the .staging-* entries in dir.
func stagingDirs(t testing.TB, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), layout.StagingPrefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// requireNonRoot skips where the kernel ignores permission bits.
func requireNonRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits, so a mode attack proves nothing here")
	}
}

// restoreMode makes dir usable again so TempDir cleanup can remove it.
func restoreMode(t testing.TB, paths ...string) {
	t.Helper()
	t.Cleanup(func() {
		for _, p := range slices.Backward(paths) {
			_ = os.Chmod(p, 0o700)
		}
	})
}

// loaded asserts the outcome loaded exactly the given set.
func loaded(t testing.TB, r result, want keySet) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("expected the set to load, got: %v\nlog:\n%s", r.err, r.log.all())
	}
	if r.keys.KeyID() != want.keyID() || !bytes.Equal(r.keys.PrivateKey(), want.priv) ||
		!bytes.Equal(r.keys.PublicKey(), want.pub) || !bytes.Equal(r.keys.RefreshSecret(), want.secret) {
		t.Fatalf("loaded key id %s, want %s: another set's material was accepted", r.keys.KeyID(), want.keyID())
	}
}

// refused asserts the outcome is an error and that neither it nor the log
// leaks anything from the sets given.
func refused(t testing.TB, r result, sets ...keySet) {
	t.Helper()
	if r.err == nil {
		t.Fatalf("expected a refusal, but authcore.New succeeded with key id %s", r.keys.KeyID())
	}
	assertNoLeak(t, "error", sets, r.err.Error(), r.log.all())
}

// sandbox is a temp tree with a KeysDir path (not created) and a sibling
// directory standing for everything an attack must not touch.
type sandbox struct {
	root, keys, outside string
}

func newSandbox(t testing.TB) sandbox {
	t.Helper()
	root := t.TempDir()
	sb := sandbox{root: root, keys: filepath.Join(root, "keys"), outside: filepath.Join(root, "outside")}
	mustMkdir(t, sb.outside)
	return sb
}

// keysDir creates the KeysDir at 0700 and returns it.
func (sb sandbox) keysDir(t testing.TB) string {
	t.Helper()
	return mustMkdir(t, sb.keys)
}

// withSet creates the KeysDir holding s.
func (sb sandbox) withSet(t testing.TB, s keySet) string {
	t.Helper()
	dir := sb.keysDir(t)
	s.writeFiles(t, dir)
	return dir
}
