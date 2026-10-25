package hostile_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/oauth"
)

func TestHostile_UserInfo_decodeCostIsBounded(t *testing.T) {
	const size = 1 << 20
	shapes := map[string]string{
		"numbers":        `{"id":1,"x":[` + strings.Repeat("1,", size/2-20) + `1]}`,
		"empty arrays":   `{"id":1,"x":[` + strings.Repeat("[],", size/3-20) + `[]]}`,
		"empty objects":  `{"id":1,"x":[` + strings.Repeat("{},", size/3-20) + `{}]}`,
		"nulls":          `{"id":1,"x":[` + strings.Repeat("null,", size/5-20) + `null]}`,
		"many keys":      `{"id":1` + strings.Repeat(`,"k":1`, size/6-20) + `}`,
		"deep nesting":   `{"id":1,"x":` + strings.Repeat("[", size-30) + strings.Repeat("]", 0) + `}`,
		"nested objects": `{"id":1,"x":` + strings.Repeat(`{"a":`, size/5-20) + `1` + strings.Repeat("}", size/5-20) + `}`,
	}
	for name, body := range shapes {
		t.Run(name, func(t *testing.T) {
			srv := serve(t, staticBody([]byte(body)))
			c := userinfoClient(t, srv.URL, nil)
			got, _ := allocOf(func() { _, _ = c.UserInfo(ctx(t), "at") })
			if got > uint64(len(body))*10 {
				t.Errorf("one call allocated %d bytes for a %d-byte body (%dx)", got, len(body), got/uint64(len(body)))
			}
		})
	}
}

func TestHostile_UserInfo_oversizedStructureIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"too many values": `{"id":1,"x":[` + strings.Repeat("1,", 20000) + `1]}`,
		"too deep":        `{"id":1,"x":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`,
	} {
		srv := serve(t, staticBody([]byte(body)))
		if info, err := userinfoClient(t, srv.URL, nil).UserInfo(ctx(t), "at"); !errors.Is(err, oauth.ErrUserInfo) {
			t.Errorf("%s: got %d keys, err = %v", name, len(info), err)
		}
	}
}

func TestHostile_UserInfo_aLargeProfileKeepsItsValuesExact(t *testing.T) {
	body := `{"id":9007199254740993,"big":123456789012345678901234567890,"f":1.50,"x":[` +
		strings.Repeat("7,", 5000) + `7],"o":{"a":[{"b":null}],"s":"t"}}`
	srv := serve(t, staticBody([]byte(body)))
	info, err := userinfoClient(t, srv.URL, nil).UserInfo(ctx(t), "at")
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"id": "9007199254740993", "big": "123456789012345678901234567890", "f": "1.50"} {
		if n, ok := info[k].(json.Number); !ok || n.String() != want {
			t.Errorf("%s = %#v, want json.Number %s", k, info[k], want)
		}
	}
	xs := info["x"].([]any)
	if len(xs) != 5001 || xs[0] != json.Number("7") {
		t.Errorf("x has %d elements", len(xs))
	}
	if o := info["o"].(map[string]any); o["s"] != "t" || o["a"].([]any)[0].(map[string]any)["b"] != nil {
		t.Errorf("o = %#v", o)
	}
}
