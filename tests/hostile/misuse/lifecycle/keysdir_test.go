package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/email"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

func quiet(dir string) authcore.Config {
	cfg := authcore.DefaultConfig()
	cfg.EnableLogs = false
	cfg.KeysDir = dir
	return cfg
}

// Several replicas starting at once against one empty volume is the normal way
// a deployment starts. Every one of them must come up with the same key set,
// not a different key per replica and not an error for the losers.
func TestMisuse_Lifecycle_concurrentNewOnOneEmptyDirAgrees(t *testing.T) {
	const n = 12
	dir := filepath.Join(t.TempDir(), "keys")
	cfg := quiet(dir)
	start := make(chan struct{})
	type result struct {
		priv, secret []byte
		err          error
	}
	out := make([]result, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ac, err := authcore.New(cfg)
			if err != nil {
				out[i].err = err
				return
			}
			out[i].priv = bytes.Clone(ac.Keys().PrivateKey())
			out[i].secret = bytes.Clone(ac.Keys().RefreshSecret())
		}()
	}
	close(start)
	wg.Wait()

	for i, r := range out {
		if r.err != nil {
			t.Fatalf("replica %d: %v", i, r.err)
		}
		if !bytes.Equal(r.priv, out[0].priv) || !bytes.Equal(r.secret, out[0].secret) {
			t.Fatalf("replica %d came up with different keys than replica 0", i)
		}
	}
	if len(out[0].priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key is %d bytes", len(out[0].priv))
	}
}

// Building again over a populated directory reloads the same keys, so a
// restart does not invalidate every token and stored hash.
func TestMisuse_Lifecycle_secondNewReloadsTheSameKeys(t *testing.T) {
	cfg := quiet(filepath.Join(t.TempDir(), "keys"))
	first, err := authcore.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := authcore.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Keys().PrivateKey(), second.Keys().PrivateKey()) ||
		!bytes.Equal(first.Keys().RefreshSecret(), second.Keys().RefreshSecret()) {
		t.Fatal("a second New over the same directory generated new keys")
	}
}

// RequireExistingKeys against an empty or missing directory is an error and
// leaves the directory exactly as it found it: a volume that failed to mount
// must not be silently populated with fresh keys.
func TestMisuse_Lifecycle_loadOnlyNeverCreatesKeys(t *testing.T) {
	empty := t.TempDir()
	missing := filepath.Join(t.TempDir(), "never-mounted")
	for name, dir := range map[string]string{"empty": empty, "missing": missing} {
		t.Run(name, func(t *testing.T) {
			cfg := quiet(dir)
			cfg.RequireExistingKeys = true
			var err error
			hostiletest.NoPanic(t, "authcore.New", func() { _, err = authcore.New(cfg) })
			if err == nil {
				t.Fatal("New succeeded without any key files")
			}
			if !errors.Is(err, authcore.ErrInvalidConfig) && !errors.Is(err, authcore.ErrKeyManager) {
				t.Fatalf("error %v wraps neither ErrInvalidConfig nor ErrKeyManager", err)
			}
		})
	}
	if entries, err := os.ReadDir(empty); err != nil || len(entries) != 0 {
		t.Errorf("load-only New wrote into the empty directory: %v %v", entries, err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("load-only New created the missing directory: %v", err)
	}
}

// Email is the one module with a Close, kept for compatibility. Using the
// module after Close, closing twice and closing while another goroutine
// validates are all harmless.
func TestMisuse_Lifecycle_emailUseAfterCloseAndDoubleClose(t *testing.T) {
	e := hostiletest.NewEnv(t)
	m, err := email.New(e.AC)
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	m.Close()
	hostiletest.NoPanic(t, "use after Close", func() {
		got, err := m.ValidateAndNormalize("  Ana.Lopez@Example.COM ")
		if err != nil || got != "ana.lopez@example.com" {
			t.Errorf("after Close: %q, %v", got, err)
		}
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.VerifyDomain(cancelled, "ana.lopez@example.invalid"); err == nil {
			t.Error("a cancelled context still produced a successful MX verdict")
		}
	})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() { defer wg.Done(); m.Close() }()
		go func() {
			defer wg.Done()
			if _, err := m.ValidateAndNormalize("ana@example.com"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
