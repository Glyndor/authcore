//go:build unix

package hostile

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"
	"text/template"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/internal/keymanager"
	"github.com/Glyndor/authcore/internal/keymanager/pemcodec"
)

// Class 8: no formatting path may print key material. Every verb fmt knows is
// applied to the key manager, to the objects that hold one in an unexported
// field (which fmt reflects through, and was the source of a real leak), and
// to the encoders and loggers a consumer would hand it to.

var allVerbs = []string{
	"%v", "%+v", "%#v", "%s", "%+s", "%#s", "%q", "%+q", "%#q", "%x", "%X", "% x", "%#x", "%08x", "%d", "%o", "%O", "%b",
	"%c", "%U", "%e", "%E", "%f", "%g", "%G", "%t", "%p", "%T", "%5v", "%-48s", "%.3s", "%10.2v", "%[1]v", "%[1]s", "%!", "%z",
}

type holder struct{ keys authcore.Keys }
type exported struct{ Keys authcore.Keys }
type nested struct {
	name string
	h    *holder
	any  any
}

// subjects returns the values a hostile logging statement could be handed.
func subjects(t *testing.T, s keySet) map[string]any {
	t.Helper()
	sb := newSandbox(t)
	dir := sb.withSet(t, s)
	auth, err := authcore.New(authcore.Config{KeysDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	keys := auth.Keys()
	store, err := authcore.NewKeyStoreFromKeys(s.priv, s.pub, s.secret)
	if err != nil {
		t.Fatal(err)
	}
	pemStore, err := authcore.NewKeyStoreFromPEM(s.privPEM, s.pubPEM, s.secret)
	if err != nil {
		t.Fatal(err)
	}
	fromKeys, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	km, err := keymanager.FromKeys(s.priv, s.pub, s.secret)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"Keys interface":         keys,
		"AuthCore pointer":       auth,
		"AuthCore copy":          *auth,
		"in-memory KeyStore":     store,
		"PEM KeyStore":           pemStore,
		"Keys from a KeyStore":   fromKeys,
		"*KeyManager":            km,
		"pointer to the pointer": &km,
		"pointer to the iface":   &keys,
		"struct, unexported":     holder{keys},
		"struct pointer, unexp.": &holder{keys},
		"struct, exported":       exported{keys},
		"nested":                 nested{"n", &holder{keys}, keys},
		"slice":                  []authcore.Keys{keys, fromKeys},
		"array":                  [1]authcore.Keys{keys},
		"map value":              map[string]authcore.Keys{"k": keys},
		"map key holder":         map[string]*holder{"k": {keys}},
		"any slice":              []any{keys, auth, store},
		"error wrapping":         fmt.Errorf("start failed: %w", errors.New(fmt.Sprint(keys))),
		"joined errors":          errors.Join(errors.New("a"), fmt.Errorf("%v", keys)),
		"nil KeyManager":         (*keymanager.KeyManager)(nil),
		"channel of keys":        make(chan authcore.Keys, 1),
		"func":                   func() authcore.Keys { return keys },
	}
}

func TestHostile_Redaction_noVerbPrintsKeyMaterial(t *testing.T) {
	s := newSet(t)
	sets := []keySet{s}
	for name, subject := range subjects(t, s) {
		for _, verb := range allVerbs {
			t.Run(name+" "+verb, func(t *testing.T) {
				var out string
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Errorf("formatting panicked: %v", r)
						}
					}()
					out = fmt.Sprintf(verb, subject)
				}()
				assertNoLeak(t, "Sprintf("+verb+")", sets, out)
			})
		}
		assertNoLeak(t, name+" Sprint", sets, fmt.Sprint(subject), fmt.Sprintln(subject))
		assertNoLeak(t, name+" Errorf", sets, fmt.Errorf("ctx: %v and %+v and %#v", subject, subject, subject).Error())
		var buf bytes.Buffer
		_, _ = fmt.Fprintf(&buf, "%v|%+v|%#v|%s|%q", subject, subject, subject, subject, subject)
		assertNoLeak(t, name+" Fprintf", sets, buf.String())
	}
}

func TestHostile_Redaction_encodersAndLoggersNeverSeeTheMaterial(t *testing.T) {
	s := newSet(t)
	sets := []keySet{s}
	subs := subjects(t, s)
	for name, subject := range subs {
		t.Run(name, func(t *testing.T) {
			if b, err := json.Marshal(subject); err == nil {
				assertNoLeak(t, "json.Marshal", sets, string(b))
			}
			if b, err := json.MarshalIndent(map[string]any{"keys": subject}, "", " "); err == nil {
				assertNoLeak(t, "json.MarshalIndent", sets, string(b))
			}
			var g bytes.Buffer
			func() {
				// gob panics on a nil pointer; that panic is the encoder's, not a leak.
				defer func() { _ = recover() }()
				if err := gob.NewEncoder(&g).Encode(subject); err == nil {
					assertNoLeak(t, "gob", sets, g.String())
				}
			}()
			if b, err := xml.Marshal(subject); err == nil {
				assertNoLeak(t, "xml.Marshal", sets, string(b))
			}

			var tpl bytes.Buffer
			tm := template.Must(template.New("t").Parse(`{{.}}|{{printf "%v %+v %#v %s" . . . .}}`))
			if err := tm.Execute(&tpl, subject); err == nil {
				assertNoLeak(t, "text/template", sets, tpl.String())
			}

			var text, js bytes.Buffer
			slog.New(slog.NewTextHandler(&text, &slog.HandlerOptions{Level: slog.LevelDebug})).
				Info("keys", "k", subject, slog.Any("a", subject), slog.Group("g", "k", subject))
			slog.New(slog.NewJSONHandler(&js, &slog.HandlerOptions{Level: slog.LevelDebug})).
				Error("keys", "k", subject, slog.Any("a", subject), slog.Group("g", "k", subject))
			assertNoLeak(t, "slog text", sets, text.String())
			assertNoLeak(t, "slog json", sets, js.String())

			var std bytes.Buffer
			l := log.New(&std, "", log.Lshortfile)
			l.Printf("%v %+v %#v %s", subject, subject, subject, subject)
			l.Println(subject)
			assertNoLeak(t, "log", sets, std.String())
		})
	}
}

func TestHostile_Redaction_theKeyManagerStillAnswersToItsOwnVerbs(t *testing.T) {
	s := newSet(t)
	km, err := keymanager.FromKeys(s.priv, s.pub, s.secret)
	if err != nil {
		t.Fatal(err)
	}
	// A redaction that blanked everything would pass every leak check above.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		out := fmt.Sprintf(verb, km)
		if !strings.Contains(out, "REDACTED") || !strings.Contains(out, s.keyID()) {
			t.Errorf("%s printed %q: expected the key id and a redaction marker", verb, out)
		}
	}
}

func TestHostile_Redaction_failuresNeverEchoTheInputs(t *testing.T) {
	a, b := newSet(t), newSet(t)
	short := a.secret[:7]
	cases := map[string]func() error{
		"private from A, public from B": func() error {
			_, err := authcore.NewKeyStoreFromPEM(a.privPEM, b.pubPEM, a.secret)
			return err
		},
		"public in the private slot": func() error {
			_, err := authcore.NewKeyStoreFromPEM(a.pubPEM, a.pubPEM, a.secret)
			return err
		},
		"private in the public slot": func() error {
			_, err := authcore.NewKeyStoreFromPEM(a.privPEM, a.privPEM, a.secret)
			return err
		},
		"short secret": func() error {
			_, err := authcore.NewKeyStoreFromPEM(a.privPEM, a.pubPEM, short)
			return err
		},
		"secret from B": func() error {
			_, err := authcore.NewKeyStoreFromKeys(a.priv, b.pub, a.secret)
			return err
		},
		"private truncated": func() error {
			_, err := authcore.NewKeyStoreFromPEM(a.privPEM[:len(a.privPEM)/2], a.pubPEM, a.secret)
			return err
		},
		"garbage with the secret appended": func() error {
			_, err := authcore.NewKeyStoreFromPEM(append(append([]byte("junk"), a.secret...), a.privPEM...), a.pubPEM, a.secret)
			return err
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			err := fn()
			if err == nil {
				t.Fatal("expected an error")
			}
			assertNoLeak(t, "error", []keySet{a, b}, err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err))
			if !errors.Is(err, authcore.ErrKeyManager) {
				t.Errorf("the error does not wrap ErrKeyManager: %v", err)
			}
		})
	}
}

func TestHostile_Redaction_successfulStartLogsNoMaterial(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.withSet(t, s)
	for _, loadOnly := range []bool{false, true} {
		r := open(t, dir, loadOnly)
		loaded(t, r, s)
		assertNoLeak(t, "startup log", []keySet{s}, r.log.all())
	}
	fresh := open(t, sb.keys+"-fresh", false)
	if fresh.err != nil {
		t.Fatal(fresh.err)
	}
	privPEM, err := pemcodec.EncodePrivateKeyPEM(fresh.keys.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	generated := keySet{priv: fresh.keys.PrivateKey(), secret: fresh.keys.RefreshSecret(), privPEM: privPEM}
	assertNoLeak(t, "generation log", []keySet{generated}, fresh.log.all())
}

func TestHostile_Redaction_inputBuffersWipedAfterConstructionDoNotBlankTheManager(t *testing.T) {
	s := newSet(t)
	priv := append([]byte{}, s.priv...)
	pub := append([]byte{}, s.pub...)
	secret := append([]byte{}, s.secret...)
	km, err := keymanager.FromKeys(priv, pub, secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{priv, pub, secret} {
		clear(b)
	}
	if !bytes.Equal(km.PrivateKey(), s.priv) || !bytes.Equal(km.PublicKey(), s.pub) || !bytes.Equal(km.RefreshSecret(), s.secret) {
		t.Error("wiping the caller's buffers changed the live key material")
	}
}
