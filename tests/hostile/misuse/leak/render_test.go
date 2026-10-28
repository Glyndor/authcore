// Package leak hands the types a developer is likely to log, print or marshal
// to fmt, encoding/json, log and slog, and checks that none of them shows key
// material. A single log.Printf("%+v", x) during an incident is the usual way
// a signing key reaches log storage.
package leak

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/field"
	"github.com/Glyndor/authcore/tests/hostile/misuse/hostiletest"
)

// target is one value a developer might hand to a logger.
type target struct {
	name string
	v    any
}

// renderings returns every way the standard library turns v into text.
func renderings(v any) map[string]string {
	out := map[string]string{
		"%v":  fmt.Sprintf("%v", v),
		"%+v": fmt.Sprintf("%+v", v),
		"%#v": fmt.Sprintf("%#v", v),
		"%s":  fmt.Sprintf("%s", v),
		"%x":  fmt.Sprintf("%x", v),
		"%d":  fmt.Sprintf("%d", v),
	}
	var buf bytes.Buffer
	log.New(&buf, "", 0).Printf("%+v", v)
	out["log.Printf"] = buf.String()
	if b, err := json.Marshal(v); err == nil {
		out["json.Marshal"] = string(b)
	}
	if b, err := json.MarshalIndent(v, "", " "); err == nil {
		out["json.MarshalIndent"] = string(b)
	}
	buf.Reset()
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "v", v)
	out["slog.Text"] = buf.String()
	buf.Reset()
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", slog.Any("v", v))
	out["slog.JSON"] = buf.String()
	return out
}

func checkAll(t *testing.T, targets []target, secrets ...[]byte) {
	t.Helper()
	for _, tg := range targets {
		for verb, text := range renderings(tg.v) {
			hostiletest.NoLeak(t, tg.name+" via "+verb, text, secrets...)
		}
	}
}

// The values the key store and the AuthCore hand out must stay quiet.
func TestMisuse_Leak_keyHoldersStayQuiet(t *testing.T) {
	e := hostiletest.NewEnv(t)
	ks, err := authcore.NewKeyStoreFromKeys(e.Mat.Clone().Priv, e.Mat.Clone().Pub, e.Mat.Clone().Secret)
	if err != nil {
		t.Fatal(err)
	}
	keys := e.AC.Keys()
	checkAll(t, []target{
		{"AuthCore pointer", e.AC},
		{"Keys()", keys},
		{"Config with KeyStore", e.Conf},
		{"Config pointer", &e.Conf},
		{"KeyStore", ks},
		{"Provider.Config()", e.AC.Config()},
	}, e.Mat.Priv, e.Mat.Priv.Seed(), e.Mat.Secret)
}

// The field module derives its keys from the refresh secret and keeps only the
// derivations. Printing it must not show either the secret or the signing key.
func TestMisuse_Leak_fieldModuleStaysQuiet(t *testing.T) {
	e := hostiletest.NewEnv(t)
	fd, err := field.New(e.AC, field.Config{Context: "users.email"})
	if err != nil {
		t.Fatal(err)
	}
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(e.Mat.Secret)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("authcore/field/blind-index/v1"))
	expand.Write([]byte{1})
	idxKey := expand.Sum(nil)
	mac := hmac.New(sha256.New, idxKey)
	context, value := "users.email", "probe"
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(context))))
	mac.Write([]byte(context))
	mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(value))))
	mac.Write([]byte(value))
	if got, err := fd.BlindIndex(value); err != nil || got != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("independently derived key does not reproduce the blind index")
	}
	for name, out := range map[string]string{
		"hex": hex.EncodeToString(idxKey), "base64": base64.StdEncoding.EncodeToString(idxKey),
		"bytes": fmt.Sprintf("%v", idxKey), "hex bytes": fmt.Sprintf("%#v", idxKey),
	} {
		if len(hostiletest.Leaks(out, idxKey)) == 0 {
			t.Fatalf("detector missed the derived key as %s", name)
		}
	}
	var nilField *field.Field
	targets := []target{{"field.Field pointer", fd}, {"field.Field value", *fd}, {"field.Field nil", nilField}}
	checkAll(t, targets, e.Mat.Priv, e.Mat.Priv.Seed(), e.Mat.Secret, idxKey)
	for _, tg := range targets {
		for verb, out := range renderings(tg.v) {
			if strings.Contains(out, string(idxKey)) {
				t.Errorf("%s via %s contains the derived key bytes", tg.name, verb)
			}
		}
	}
}
