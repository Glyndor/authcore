//go:build unix

// Package hostiletest holds the fixtures shared by the hostile key store
// suites, one package per attack class under tests/hostile/keymanager. Those
// suites attack the on-disk key store from the outside. The
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
// test in these packages runs in parallel.
package hostiletest

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
	Lines []string
}

func (r *recLog) add(level, msg string, args []any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Lines = append(r.Lines, level+" "+fmt.Sprintf(msg, args...))
}

func (r *recLog) Debug(msg string, args ...any) { r.add("DEBUG", msg, args) }
func (r *recLog) Info(msg string, args ...any)  { r.add("INFO", msg, args) }
func (r *recLog) Warn(msg string, args ...any)  { r.add("WARN", msg, args) }
func (r *recLog) Error(msg string, args ...any) { r.add("ERROR", msg, args) }

// All returns every message joined, for leak and substring checks.
func (r *recLog) All() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.Lines, "\n")
}

func (r *recLog) Has(fragment string) bool { return strings.Contains(r.All(), fragment) }

// KeySet is one complete, valid key set in memory.
type KeySet struct {
	Priv      ed25519.PrivateKey
	Pub       ed25519.PublicKey
	Secret    []byte
	PrivPEM   []byte
	PubPEM    []byte
	SecretHex []byte
}

// NewSet generates one complete, valid key set.
func NewSet(t testing.TB) KeySet {
	t.Helper()
	// None of these can fail for well-formed input and a working crypto/rand.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	secret := make([]byte, layout.RefreshSecretLen)
	_, _ = rand.Read(secret)
	privPEM, _ := pemcodec.EncodePrivateKeyPEM(priv)
	pubPEM, _ := pemcodec.EncodePublicKeyPEM(pub)
	return KeySet{priv, pub, secret, privPEM, pubPEM, append([]byte(hex.EncodeToString(secret)), '\n')}
}

// WriteFiles lays the three key files into dir with the modes authcore uses.
func (s KeySet) WriteFiles(t testing.TB, dir string) {
	t.Helper()
	Put(t, filepath.Join(dir, layout.FilePrivateKey), s.PrivPEM, 0o600)
	Put(t, filepath.Join(dir, layout.FilePublicKey), s.PubPEM, 0o644)
	Put(t, filepath.Join(dir, layout.FileRefreshSecret), s.SecretHex, 0o600)
}

// KeyID is the identifier authcore derives for the set.
func (s KeySet) KeyID() string {
	h := sha256.Sum256(s.Pub)
	return hex.EncodeToString(h[:8])
}

// Needles lists the encodings in which the private material could leak: hex,
// base64, the decimal byte slice %v prints and the Go-syntax hex %#v prints.
func (s KeySet) Needles() []string {
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
		hex.EncodeToString(s.Priv), hex.EncodeToString(s.Priv.Seed()), hex.EncodeToString(s.Secret),
		base64.StdEncoding.EncodeToString(s.Priv), base64.StdEncoding.EncodeToString(s.Priv.Seed()),
		base64.RawURLEncoding.EncodeToString(s.Priv.Seed()), base64.StdEncoding.EncodeToString(s.Secret),
		body(s.PrivPEM), decimal(s.Priv.Seed()), decimal(s.Secret), goSyntax(s.Priv.Seed()), goSyntax(s.Secret),
	}
}

// AssertNoLeak fails when any text carries private material of any set given.
func AssertNoLeak(t testing.TB, what string, sets []KeySet, texts ...string) {
	t.Helper()
	for _, text := range texts {
		for _, s := range sets {
			for _, n := range s.Needles() {
				if strings.Contains(text, n) {
					t.Errorf("%s leaks key material (%.12s...): %.200q", what, n, text)
				}
			}
		}
	}
}

// Put writes data to path and forces mode past the umask.
func Put(t testing.TB, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// Read returns the content of path or fails the test.
func Read(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MustMkdir creates path and its parents at 0700 and returns it.
func MustMkdir(t testing.TB, path string) string {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// MustSymlink makes link point at target.
func MustSymlink(t testing.TB, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// Result is what authcore.New reported.
type Result struct {
	Keys authcore.Keys
	Log  *recLog
	Err  error
}

// Open runs authcore.New against dir under a deadline, so a hostile entry that
// makes the loader block is a failure rather than a hung suite.
func Open(t testing.TB, dir string, loadOnly bool) Result {
	t.Helper()
	log := &recLog{}
	done := make(chan Result, 1)
	go func() {
		a, err := authcore.New(authcore.Config{KeysDir: dir, Logger: log, RequireExistingKeys: loadOnly})
		var keys authcore.Keys
		if a != nil {
			keys = a.Keys()
		}
		done <- Result{keys, log, err}
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("authcore.New(%q, loadOnly=%v) did not return within 10s", dir, loadOnly)
		return Result{}
	}
}

// BothModes runs fn once for the writable store and once for load-only.
func BothModes(t *testing.T, fn func(t *testing.T, loadOnly bool)) {
	t.Helper()
	t.Run("new", func(t *testing.T) { fn(t, false) })
	t.Run("load", func(t *testing.T) { fn(t, true) })
}

// Entry is one node of a tree snapshot.
type Entry string

// Tree snapshots root without following links: path to kind, mode and content
// hash, or the link target. Two equal snapshots mean nothing changed.
func Tree(t testing.TB, root string) map[string]Entry {
	t.Helper()
	out := map[string]Entry{}
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
			out[rel] = Entry("link->" + dst)
		case fi.IsDir():
			out[rel] = Entry(fmt.Sprintf("dir %04o", fi.Mode().Perm()))
		case fi.Mode().IsRegular() && fi.Size() > 1<<20:
			// Too big to hash cheaply; the size and mode still catch a rewrite.
			out[rel] = Entry(fmt.Sprintf("big file %04o %d", fi.Mode().Perm(), fi.Size()))
		case fi.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				out[rel] = Entry(fmt.Sprintf("unreadable %04o", fi.Mode().Perm()))
				return nil
			}
			sum := sha256.Sum256(data)
			out[rel] = Entry(fmt.Sprintf("file %04o %x", fi.Mode().Perm(), sum[:6]))
		default:
			out[rel] = Entry("special " + fi.Mode().Type().String())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// AssertSame fails when the tree under root differs from before.
func AssertSame(t testing.TB, what string, before, after map[string]Entry) {
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

// StagingDirs lists the .staging-* entries in dir.
func StagingDirs(t testing.TB, dir string) []string {
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

// RequireNonRoot skips where the kernel ignores permission bits.
func RequireNonRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits, so a mode attack proves nothing here")
	}
}

// RestoreMode makes dir usable again so TempDir cleanup can remove it.
func RestoreMode(t testing.TB, paths ...string) {
	t.Helper()
	t.Cleanup(func() {
		for _, p := range slices.Backward(paths) {
			_ = os.Chmod(p, 0o700)
		}
	})
}

// Loaded asserts the outcome loaded exactly the given set.
func Loaded(t testing.TB, r Result, want KeySet) {
	t.Helper()
	if r.Err != nil {
		t.Fatalf("expected the set to load, got: %v\nlog:\n%s", r.Err, r.Log.All())
	}
	if r.Keys.KeyID() != want.KeyID() || !bytes.Equal(r.Keys.PrivateKey(), want.Priv) ||
		!bytes.Equal(r.Keys.PublicKey(), want.Pub) || !bytes.Equal(r.Keys.RefreshSecret(), want.Secret) {
		t.Fatalf("loaded key id %s, want %s: another set's material was accepted", r.Keys.KeyID(), want.KeyID())
	}
}

// Refused asserts the outcome is an error and that neither it nor the log
// leaks anything from the sets given.
func Refused(t testing.TB, r Result, sets ...KeySet) {
	t.Helper()
	if r.Err == nil {
		t.Fatalf("expected a refusal, but authcore.New succeeded with key id %s", r.Keys.KeyID())
	}
	AssertNoLeak(t, "error", sets, r.Err.Error(), r.Log.All())
}

// Sandbox is a temp tree with a KeysDir path (not created) and a sibling
// directory standing for everything an attack must not touch.
type Sandbox struct {
	Root, Keys, Outside string
}

// NewSandbox builds a temp tree with a KeysDir path and an outside directory.
func NewSandbox(t testing.TB) Sandbox {
	t.Helper()
	root := t.TempDir()
	sb := Sandbox{Root: root, Keys: filepath.Join(root, "keys"), Outside: filepath.Join(root, "outside")}
	MustMkdir(t, sb.Outside)
	return sb
}

// KeysDir creates the KeysDir at 0700 and returns it.
func (sb Sandbox) KeysDir(t testing.TB) string {
	t.Helper()
	return MustMkdir(t, sb.Keys)
}

// WithSet creates the KeysDir holding s.
func (sb Sandbox) WithSet(t testing.TB, s KeySet) string {
	t.Helper()
	dir := sb.KeysDir(t)
	s.WriteFiles(t, dir)
	return dir
}
