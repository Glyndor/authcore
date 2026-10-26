package credential_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/Glyndor/authcore/auth/credential"
)

func TestRedactedRenderings(t *testing.T) {
	var m credential.Credential
	var nilPtr *credential.Credential
	want := map[string]string{
		"%v": "credential.Credential{redacted}", "%+v": "credential.Credential{redacted}", "%s": "credential.Credential{redacted}",
		"%#v": "&credential.Credential{redacted}", "%x": "%!x(credential.Credential)",
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
	if got := nilPtr.GoString(); got != "(*credential.Credential)(nil)" {
		t.Errorf("nil GoString() = %q", got)
	}
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "m", &m, "n", nilPtr)
	if got := buf.String(); !bytes.Contains(buf.Bytes(), []byte("m=credential.Credential{redacted}")) || !bytes.Contains(buf.Bytes(), []byte("n=<nil>")) {
		t.Errorf("slog = %q", got)
	}
}
