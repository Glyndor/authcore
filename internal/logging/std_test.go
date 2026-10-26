package logging_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/logging"
)

func TestStdWritesOneLinePerEntryAtItsLevel(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := logging.NewStd(&buf)
	l.Debug("d %d", 1)
	l.Info("i %s", "x")
	l.Warn("w %v", true)
	l.Error("e %s", "boom")

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	want := []struct{ prefix, msg string }{
		{"[DEBUG] authcore: ", "d 1"},
		{"[INFO]  authcore: ", "i x"},
		{"[WARN]  authcore: ", "w true"},
		{"[ERROR] authcore: ", "e boom"},
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(lines), len(want), buf.String())
	}
	stamp := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) (.*)$`)
	for i, w := range want {
		rest, ok := strings.CutPrefix(lines[i], w.prefix)
		if !ok {
			t.Errorf("line %d = %q, want prefix %q", i, lines[i], w.prefix)
			continue
		}
		m := stamp.FindStringSubmatch(rest)
		if m == nil || m[2] != w.msg {
			t.Errorf("line %d body = %q, want a timestamp then %q", i, rest, w.msg)
			continue
		}
		at, err := time.Parse("2006/01/02 15:04:05", m[1])
		if err != nil {
			t.Fatal(err)
		}
		// The stamp is UTC, whatever the machine's zone.
		if d := time.Since(at); d < -time.Minute || d > time.Minute {
			t.Errorf("line %d stamp %s is %v from UTC now", i, m[1], d)
		}
	}
}

func TestNoopDiscardsEverything(t *testing.T) {
	t.Parallel()
	var n logging.Noop
	n.Debug("a %d", 1)
	n.Info("b")
	n.Warn("c")
	n.Error("d")
}
