package authcore

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
)

// Every value an application might log that holds key material, formatted
// with every verb, must not contain that material in any encoding fmt uses
// for bytes. The *KeyManager inside them redacts itself when formatted
// directly, but fmt reaches it through an unexported field, where Format is
// not called; until 2026-09-25 the verbs a pointer does not support (%s, %q,
// %t, ...) dereferenced it and printed the private key and refresh secret.

var formatVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%c", "%e", "%f", "%U", "%o", "%b"}

// encodings returns how fmt can render the leading bytes of b: decimal inside
// a slice, lowercase and uppercase hex, and the 0x-prefixed %#v form.
func encodings(b []byte) []string {
	head := b[:8]
	dec := make([]string, len(head))
	gohex := make([]string, len(head))
	for i, v := range head {
		dec[i] = fmt.Sprint(v)
		gohex[i] = fmt.Sprintf("0x%x", v)
	}
	return []string{
		strings.Join(dec, " "),
		fmt.Sprintf("%x", head),
		fmt.Sprintf("%X", head),
		strings.Join(gohex, ", "),
	}
}

func TestFormattingNeverPrintsKeyMaterial(t *testing.T) {
	seed := bytes.Repeat([]byte{0xD7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	secret := bytes.Repeat([]byte{0xAB}, 32)
	store, err := NewKeyStoreFromKeys(priv, priv.Public().(ed25519.PublicKey), secret)
	if err != nil {
		t.Fatalf("NewKeyStoreFromKeys: %v", err)
	}
	cfg := DefaultConfig()
	cfg.KeyStore = store
	ac, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	diskCfg := DefaultConfig()
	diskCfg.KeysDir = t.TempDir()
	onDisk, err := New(diskCfg)
	if err != nil {
		t.Fatalf("New on disk: %v", err)
	}

	type target struct {
		value   any
		secrets [][]byte
	}
	targets := map[string]target{
		"*AuthCore (KeyStore)": {ac, [][]byte{priv, secret}},
		"AuthCore (KeyStore)":  {*ac, [][]byte{priv, secret}},
		"Config with KeyStore": {cfg, [][]byte{priv, secret}},
		"ac.Config()":          {ac.Config(), [][]byte{priv, secret}},
		"the KeyStore":         {store, [][]byte{priv, secret}},
		"*AuthCore (disk)":     {onDisk, [][]byte{onDisk.Keys().PrivateKey(), onDisk.Keys().RefreshSecret()}},
	}

	for name, tg := range targets {
		for _, verb := range formatVerbs {
			out := fmt.Sprintf(verb, tg.value)
			if out == "" {
				t.Fatalf("%s %s printed nothing; the check would prove nothing", name, verb)
			}
			for _, s := range tg.secrets {
				for _, enc := range encodings(s) {
					if strings.Contains(out, enc) {
						t.Errorf("%s formatted with %s contains key material (%q)", name, verb, enc)
					}
				}
			}
		}
	}
}
