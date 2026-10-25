//go:build unix

package hostile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/internal/keymanager/layout"
)

// Class 6, metadata.json: version markers, duplicated fields, JSON bombs and
// rollback to an earlier key set.

func metaPath(dir string) string { return filepath.Join(dir, layout.FileMetadata) }

func TestHostile_Metadata_hostileContentIsRefusedAndNeverRewritten(t *testing.T) {
	deep := strings.Repeat("[", 3000) + strings.Repeat("]", 3000)
	cases := map[string]string{
		"future format 2":          `{"format":2,"created":"2030-01-01T00:00:00Z","key_id":"x"}`,
		"future format 99":         `{"format":99}`,
		"max int64 format":         `{"format":9223372036854775807}`,
		"overflowing format":       `{"format":18446744073709551616}`,
		"huge exponent":            `{"format":1e999}`,
		"format 0":                 `{"format":0}`,
		"negative format":          `{"format":-1}`,
		"empty object":             `{}`,
		"null":                     `null`,
		"array":                    `[1]`,
		"string":                   `"format"`,
		"number":                   `1`,
		"format as string":         `{"format":"1"}`,
		"format as float":          `{"format":1.5}`,
		"format as bool":           `{"format":true}`,
		"format as object":         `{"format":{"v":1}}`,
		"duplicate, future last":   `{"format":1,"format":99}`,
		"empty file":               ``,
		"whitespace only":          " \n\t ",
		"truncated":                `{"format":1,"created":"2020`,
		"unterminated string":      `{"format":1,"key_id":"abc`,
		"BOM first":                "\xef\xbb\xbf" + `{"format":1}`,
		"NUL inside":               "{\"format\":1,\"key_id\":\"a\x00b\"} \x00",
		"invalid UTF-8 then bad":   "{\"format\":1,\"key_id\":\"\xff\xfe\"} }",
		"trailing second object":   `{"format":1}{"format":99}`,
		"nesting bomb":             deep,
		"nesting bomb in a field":  `{"format":1,"x":` + deep + `}x`,
		"over the 4 KiB cap":       `{"format":1,"key_id":"` + strings.Repeat("A", layout.MaxKeyFileSize) + `"}`,
		"digits bomb":              `{"format":` + strings.Repeat("9", 4000) + `}`,
		"comment":                  `{"format":1} // ok`,
		"single quotes":            `{'format':1}`,
		"unquoted key":             `{format:1}`,
		"trailing comma":           `{"format":1,}`,
		"binary":                   "\x00\x01\x02\x03\xff\xfe",
		"a PEM instead of JSON":    string(newSet(t).privPEM),
		"huge number of fields":    `{"format":1` + strings.Repeat(`,"k":1`, 600) + `,"format":99}`,
		"future format after dups": `{"format":1,"format":1,"format":3}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				sb := newSandbox(t)
				s := newSet(t)
				dir := sb.withSet(t, s)
				put(t, metaPath(dir), []byte(content), 0o600)
				before := keyTree(t, dir)

				refused(t, open(t, dir, loadOnly), s)

				assertSame(t, "KeysDir", before, keyTree(t, dir))
			})
		})
	}
}

func TestHostile_Metadata_leniencyThatIsSafeToKeep(t *testing.T) {
	cases := map[string]string{
		"only the format":                        `{"format":1}`,
		"unknown extra fields":                   `{"format":1,"created":"x","key_id":"y","from_the_future":{"a":[1,2]}}`,
		"whitespace and CRLF":                    "\r\n {\r\n \"format\" : 1 \r\n}\r\n",
		"duplicate, last wins and is current":    `{"format":99,"format":1}`,
		"key id with control characters":         `{"format":1,"key_id":"\u001b[31m\n\r"}`,
		"created is not a time":                  `{"format":1,"created":"yesterday-ish"}`,
		"format written with an exponent of one": `{"format":1.0}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			sb := newSandbox(t)
			s := newSet(t)
			dir := sb.withSet(t, s)
			put(t, metaPath(dir), []byte(content), 0o600)

			r := open(t, dir, false)

			if r.err != nil {
				// Refusing is also safe; what is not allowed is loading anything else.
				refused(t, r, s)
				return
			}
			loaded(t, r, s)
			for _, line := range r.log.lines {
				if strings.ContainsAny(line, "\x1b\r") || strings.Contains(line, "\n") {
					t.Errorf("metadata content reached a log line raw: %q", line)
				}
			}
		})
	}
}

func TestHostile_Metadata_loadOnlyNeverRewritesAMismatchingMarker(t *testing.T) {
	sb := newSandbox(t)
	s := newSet(t)
	dir := sb.withSet(t, s)
	put(t, metaPath(dir), []byte(`{"format":1,"created":"2020-01-01T00:00:00Z","key_id":"0000000000000000"}`+"\n"), 0o600)
	before := tree(t, dir)

	loaded(t, open(t, dir, true), s)

	assertSame(t, "KeysDir after load-only", before, tree(t, dir))
}

func TestHostile_Metadata_rollbackToAnEarlierSetIsLoudAndNeverMixed(t *testing.T) {
	sb := newSandbox(t)
	older, newer := newSet(t), newSet(t)
	dir := sb.withSet(t, older)
	first := open(t, dir, false)
	loaded(t, first, older)

	// Rotation forward: the operator replaces the whole set.
	newer.writeFiles(t, dir)
	for _, n := range layout.KeyFileNames() {
		if err := os.Chmod(filepath.Join(dir, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	forward := open(t, dir, false)
	loaded(t, forward, newer)
	if !forward.log.has("signing key changed") {
		t.Errorf("a changed signing key was adopted silently:\n%s", forward.log.all())
	}

	// Rollback: an older backup is restored over the new set.
	older.writeFiles(t, dir)
	back := open(t, dir, false)
	loaded(t, back, older)
	if !back.log.has("signing key changed") {
		t.Errorf("a rollback to the earlier set was adopted silently:\n%s", back.log.all())
	}
	if !strings.Contains(string(read(t, metaPath(dir))), older.keyID()) {
		t.Error("metadata.json does not record the restored key id")
	}
}

func TestHostile_Metadata_markerWithoutKeysNeverRegenerates(t *testing.T) {
	hostileIDs := []string{
		"0123456789abcdef",
		"x\n[FATAL] forged log line",
		"\x1b[2J\x1b[31mred\r",
		strings.Repeat("A", 3000),
		"%s%s%n",
		"\u202eevil",
	}
	for i, id := range hostileIDs {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			bothModes(t, func(t *testing.T, loadOnly bool) {
				sb := newSandbox(t)
				dir := sb.keysDir(t)
				body := `{"format":1,"created":"2020-01-01T00:00:00Z","key_id":` + jsonString(id) + `}` + "\n"
				put(t, metaPath(dir), []byte(body), 0o600)

				r := open(t, dir, loadOnly)

				refused(t, r)
				for _, n := range layout.KeyFileNames() {
					if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
						t.Errorf("%s was generated although metadata.json says a set existed", n)
					}
				}
				if msg := r.err.Error(); strings.ContainsAny(msg, "\x1b\r") || strings.Contains(msg, "\n") {
					t.Errorf("a hostile key id reached the error raw: %q", msg)
				}
				for _, line := range r.log.lines {
					if strings.ContainsAny(line, "\x1b\r") || strings.Contains(line, "\n") {
						t.Errorf("a hostile key id reached the log raw: %q", line)
					}
				}
			})
		})
	}
}

// jsonString quotes s as a JSON string.
func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteString(string("0123456789abcdef"[r>>4]))
			b.WriteString(string("0123456789abcdef"[r&0xf]))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
