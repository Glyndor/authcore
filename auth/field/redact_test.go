package field_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/field"
)

func TestRedactedRenderings(t *testing.T) {
	var m field.Field
	want := map[string]string{
		"%v": "field.Field{redacted}", "%+v": "field.Field{redacted}", "%s": "field.Field{redacted}",
		"%#v": "&field.Field{redacted}", "%x": "%!x(field.Field)",
	}
	for name, value := range map[string]any{"value": m, "pointer": &m} {
		for verb, expected := range want {
			if got := fmt.Sprintf(verb, value); got != expected {
				t.Errorf("%s %s does not use the redacted rendering", name, verb)
			}
		}
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "m", value)
		if !strings.Contains(buf.String(), "m=field.Field{redacted}") {
			t.Errorf("%s slog does not use the redacted rendering", name)
		}
	}
}

func TestNilRenderings(t *testing.T) {
	var p *field.Field
	if fmt.Sprint(p) != "<nil>" {
		t.Error("nil formatting does not render <nil>")
	}
	stringer, ok := any(p).(fmt.Stringer)
	if !ok {
		t.Fatal("Field does not implement Stringer")
	}
	if stringer.String() != "<nil>" {
		t.Error("nil String does not render <nil>")
	}
	goStringer, ok := any(p).(fmt.GoStringer)
	if !ok {
		t.Fatal("Field does not implement GoStringer")
	}
	if goStringer.GoString() != "(*field.Field)(nil)" {
		t.Error("nil GoString does not render the nil pointer")
	}
	valuer, ok := any(p).(slog.LogValuer)
	if !ok {
		t.Fatal("Field does not implement LogValuer")
	}
	if valuer.LogValue().String() != "<nil>" {
		t.Error("nil LogValue does not render <nil>")
	}
}
