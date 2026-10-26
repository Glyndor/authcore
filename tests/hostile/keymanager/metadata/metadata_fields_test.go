//go:build unix

package metadata

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Class 15: the same metadata.json said in different ways. The marker is parsed
// by a JSON decoder that ignores field order and folds the case of field names,
// so what matters is that no spelling of "format" or "secret_binding" slips past
// the checks that the canonical spelling triggers.

// markerFields returns the four fields of the marker a normal start wrote.
func markerFields(t testing.TB, s hostiletest.KeySet) map[string]any {
	t.Helper()
	sb := hostiletest.NewSandbox(t)
	dir := sb.WithSet(t, s)
	hostiletest.Loaded(t, hostiletest.Open(t, dir, false), s)
	var m map[string]any
	if err := json.Unmarshal(hostiletest.Read(t, metaPath(dir)), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"format", "created", "key_id", "secret_binding"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("a fresh marker has no %q: %v", k, m)
		}
	}
	return m
}

func permutations(items []string) [][]string {
	if len(items) <= 1 {
		return [][]string{items}
	}
	var out [][]string
	for i := range items {
		rest := append(append([]string(nil), items[:i]...), items[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]string{items[i]}, p...))
		}
	}
	return out
}

// object renders fields in the given order and with the given key spellings.
func object(order []string, fields map[string]any, spell func(string) string) string {
	var parts []string
	for _, k := range order {
		v, _ := json.Marshal(fields[k])
		parts = append(parts, fmt.Sprintf("%q:%s", spell(k), v))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func TestHostile_MetadataFields_everyOrderingIsReadTheSameWay(t *testing.T) {
	s := hostiletest.NewSet(t)
	fields := markerFields(t, s)
	keys := []string{"format", "created", "key_id", "secret_binding"}
	for _, order := range permutations(keys) {
		t.Run(strings.Join(order, ","), func(t *testing.T) {
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				sb := hostiletest.NewSandbox(t)
				dir := sb.WithSet(t, s)
				body := object(order, fields, func(k string) string { return k })
				hostiletest.Put(t, metaPath(dir), []byte(body), 0o600)
				before := hostiletest.KeyTree(t, dir)

				hostiletest.Loaded(t, hostiletest.Open(t, dir, loadOnly), s)

				hostiletest.AssertSame(t, "KeysDir", before, hostiletest.KeyTree(t, dir))

				// With the binding replaced by another set's, every ordering refuses.
				other := markerFields(t, hostiletest.NewSet(t))
				swapped := map[string]any{"format": 1, "created": fields["created"],
					"key_id": fields["key_id"], "secret_binding": other["secret_binding"]}
				hostiletest.Put(t, metaPath(dir), []byte(object(order, swapped, func(k string) string { return k })), 0o600)
				hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)
			})
		})
	}
}

func TestHostile_MetadataFields_caseVariantsOfNamesAreNotAWayAround(t *testing.T) {
	s := hostiletest.NewSet(t)
	fields := markerFields(t, s)
	order := []string{"format", "created", "key_id", "secret_binding"}
	spellings := map[string]func(string) string{
		"upper": strings.ToUpper,
		"title": func(k string) string { return strings.ToUpper(k[:1]) + k[1:] },
		"mixed": func(k string) string { return k[:len(k)-1] + strings.ToUpper(k[len(k)-1:]) },
	}
	for name, spell := range spellings {
		t.Run(name, func(t *testing.T) {
			hostiletest.BothModes(t, func(t *testing.T, loadOnly bool) {
				sb := hostiletest.NewSandbox(t)
				dir := sb.WithSet(t, s)

				future := map[string]any{"format": 2, "created": fields["created"], "key_id": fields["key_id"]}
				hostiletest.Put(t, metaPath(dir), []byte(object(order[:3], future, spell)), 0o600)
				hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)

				other := markerFields(t, hostiletest.NewSet(t))
				mismatch := map[string]any{"format": 1, "created": fields["created"],
					"key_id": fields["key_id"], "secret_binding": other["secret_binding"]}
				hostiletest.Put(t, metaPath(dir), []byte(object(order, mismatch, spell)), 0o600)
				hostiletest.Refused(t, hostiletest.Open(t, dir, loadOnly), s)
			})
		})
	}
}
