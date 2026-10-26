package jwt_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/Glyndor/authcore/auth/jwt"
)

func TestRedactedRenderings(t *testing.T) {
	var m jwt.JWT[struct{}]
	var nilPtr *jwt.JWT[struct{}]
	want := map[string]string{
		"%v": "jwt.JWT{redacted}", "%+v": "jwt.JWT{redacted}", "%s": "jwt.JWT{redacted}",
		"%#v": "&jwt.JWT{redacted}", "%x": "%!x(jwt.JWT)",
	}
	for verb, w := range want {
		if got := fmt.Sprintf(verb, m); got != w {
			t.Errorf("value %s = %q, want %q", verb, got, w)
		}
		if got := fmt.Sprintf(verb, &m); got != w {
			t.Errorf("pointer %s = %q, want %q", verb, got, w)
		}
	}
	if got := fmt.Sprintf("%v", nilPtr); got != "<nil>" {
		t.Errorf("nil %%v = %q", got)
	}
	if got := nilPtr.String(); got != "<nil>" {
		t.Errorf("nil String() = %q", got)
	}
	if got := nilPtr.GoString(); got != "(*jwt.JWT)(nil)" {
		t.Errorf("nil GoString() = %q", got)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "m", &m, "n", nilPtr)
	if got := buf.String(); !bytes.Contains(buf.Bytes(), []byte("m=jwt.JWT{redacted}")) || !bytes.Contains(buf.Bytes(), []byte("n=<nil>")) {
		t.Errorf("slog = %q", got)
	}
}
