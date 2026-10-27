package pemcodec

import (
	"bytes"
	"testing"
)

func TestDecodePEMBlockRejectsSkippedPrefix(t *testing.T) {
	_, _, private, public := pair(t)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"PRIVATE KEY", private}, {"PUBLIC KEY", public},
	} {
		for _, prefix := range []string{
			"junk\n",
			"-----BEGIN PRIVATE KEY-----\n",
			"-----BEGIN PRIVATE KEY-----\ninvalid!\n-----END PRIVATE KEY-----\n",
			"-----BEGIN BROKEN\n",
		} {
			t.Run(tc.name+"/"+prefix, func(t *testing.T) {
				data := append([]byte(prefix), tc.data...)
				if der, err := DecodePEMBlock(data, tc.name, "input"); err == nil || der != nil {
					t.Fatalf("skipped prefix: DER=%x, err=%v; want refusal", der, err)
				}
			})
		}
		padded := append([]byte(" \r\n\t"), tc.data...)
		padded = append(padded, []byte("\n\t ")...)
		want, err := DecodePEMBlock(tc.data, tc.name, "input")
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodePEMBlock(padded, tc.name, "input")
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("whitespace: %v", err)
		}
	}
}
