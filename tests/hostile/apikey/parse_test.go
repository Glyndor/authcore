package apikey_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/auth/apikey"
)

// A key is "<prefix>_<32 hex id>_<64 hex secret>" and the id is what the
// application uses to look the row up before it checks the secret. Anything
// that is not exactly that shape is refused with ErrInvalidKey, so a lookup is
// never keyed on attacker-shaped text.
func TestHostile_Parse_onlyTheExactShapeYieldsAnID(t *testing.T) {
	m := newModule(t)
	k, err := m.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if id, err := m.ParseID(k.Key); err != nil || id != k.ID {
		t.Fatalf("control: ParseID = %q, %v; want %q", id, err, k.ID)
	}
	id, secret := k.ID, strings.TrimPrefix(k.Key, "ak_"+k.ID+"_")
	if len(id) != 32 || len(secret) != 64 {
		t.Fatalf("test bug: id=%d secret=%d", len(id), len(secret))
	}

	cases := map[string]string{
		"empty":                "",
		"prefix only":          "ak",
		"prefix and separator": "ak_",
		"no secret":            "ak_" + id,
		"no secret, separator": "ak_" + id + "_",
		"empty id":             "ak__" + secret,
		"wrong prefix":         "sk_" + id + "_" + secret,
		"prefix upper case":    "AK_" + id + "_" + secret,
		"prefix twice":         "ak_ak_" + id + "_" + secret,
		"no prefix":            id + "_" + secret,
		"prefix without sep":   "ak" + id + "_" + secret,
		"prefix hyphen sep":    "ak-" + id + "-" + secret,
		"extra trailing field": "ak_" + id + "_" + secret + "_extra",
		"extra trailing sep":   "ak_" + id + "_" + secret + "_",
		"extra leading field":  "x_ak_" + id + "_" + secret,
		"doubled separator":    "ak_" + id + "__" + secret,
		"underscore in id":     "ak_" + id[:10] + "_" + id[11:] + "_" + secret,
		"id one short":         "ak_" + id[:31] + "_" + secret,
		"id one long":          "ak_" + id + "a_" + secret,
		"id upper case":        "ak_" + strings.ToUpper(id) + "_" + secret,
		"id non-hex":           "ak_" + strings.Repeat("g", 32) + "_" + secret,
		"id with sign":         "ak_" + "+" + id[1:] + "_" + secret,
		"id with 0x":           "ak_0x" + id[2:] + "_" + secret,
		"id fullwidth":         "ak_" + "\uff10" + id[1:] + "_" + secret,
		"id arabic-indic":      "ak_" + "\u0660" + id[1:] + "_" + secret,
		"secret one short":     "ak_" + id + "_" + secret[:63],
		"secret one long":      "ak_" + id + "_" + secret + "a",
		"secret upper case":    "ak_" + id + "_" + strings.ToUpper(secret),
		"secret non-hex":       "ak_" + id + "_" + strings.Repeat("z", 64),
		"leading space":        " " + k.Key,
		"trailing space":       k.Key + " ",
		"trailing newline":     k.Key + "\n",
		"trailing CRLF":        k.Key + "\r\n",
		"trailing NUL":         k.Key + "\x00",
		"NUL in id":            "ak_" + id[:10] + "\x00" + id[11:] + "_" + secret,
		"tab inside":           "ak_" + id + "\t_" + secret,
		"bearer prefix":        "Bearer " + k.Key,
		"quoted":               `"` + k.Key + `"`,
		"zero width space":     "ak_" + id + "\u200b_" + secret,
		"url encoded sep":      "ak%5F" + id + "_" + secret,
		"id is 1 MiB":          "ak_" + strings.Repeat("a", 1<<20) + "_" + secret,
		"secret is 1 MiB":      "ak_" + id + "_" + strings.Repeat("a", 1<<20),
		"8 MiB of underscores": strings.Repeat("_", 8<<20),
		"9 MiB of prefix":      strings.Repeat("ak_", 3<<20),
	}
	for name, key := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			got, err := m.ParseID(key)
			if got != "" || !errors.Is(err, apikey.ErrInvalidKey) {
				t.Fatalf("ParseID = %q, %v; want empty and ErrInvalidKey", got, err)
			}
			if d := time.Since(start); d > time.Second {
				t.Fatalf("refusing took %v", d)
			}
		})
	}
}

// The id that comes back never carries any part of the secret, and it is the
// id Generate reported, so a lookup by it finds the row the key belongs to.
func TestHostile_Parse_idDoesNotLeakTheSecret(t *testing.T) {
	m := newModule(t)
	for i := 0; i < 200; i++ {
		k, err := m.Generate()
		if err != nil {
			t.Fatal(err)
		}
		id, err := m.ParseID(k.Key)
		if err != nil || id != k.ID {
			t.Fatalf("ParseID = %q, %v; want %q", id, err, k.ID)
		}
		secret := strings.TrimPrefix(k.Key, "ak_"+k.ID+"_")
		if strings.Contains(id, secret[:8]) || strings.Contains(k.ID, secret[:8]) || strings.Contains(k.Hash, secret[:16]) {
			t.Fatal("the id or hash repeats part of the secret")
		}
	}
}

// Format collision between deployments: a key minted under one prefix is not
// parsed under another, including prefixes that are a prefix of each other.
func TestHostile_Parse_prefixesDoNotCollide(t *testing.T) {
	short := newModule(t, apikey.Config{Prefix: "a"})
	mid := newModule(t, apikey.Config{Prefix: "ak"})
	long := newModule(t, apikey.Config{Prefix: "akx"})
	digits := newModule(t, apikey.Config{Prefix: "0f"})

	mods := map[string]*apikey.APIKey{"a": short, "ak": mid, "akx": long, "0f": digits}
	for from, src := range mods {
		k, err := src.Generate()
		if err != nil {
			t.Fatal(err)
		}
		for to, dst := range mods {
			id, err := dst.ParseID(k.Key)
			if from == to {
				if err != nil || id != k.ID {
					t.Errorf("%s -> %s: %q, %v", from, to, id, err)
				}
				continue
			}
			if id != "" || !errors.Is(err, apikey.ErrInvalidKey) {
				t.Errorf("a key minted under %q parsed under %q: %q, %v", from, to, id, err)
			}
		}
	}
}

// The prefix is a name for humans and scanners, not a place to hide structure.
// Anything that could be read as part of the id or as a second separator is
// refused when the module is built.
func TestHostile_Parse_hostilePrefixesAreRefusedAtConstruction(t *testing.T) {
	for name, prefix := range map[string]string{
		"underscore":         "a_k",
		"leading underscore": "_ak",
		"upper case":         "AK",
		"mixed case":         "aK",
		"hyphen":             "a-k",
		"space":              "a k",
		"dot":                "a.k",
		"slash":              "a/k",
		"NUL":                "a\x00k",
		"newline":            "ak\n",
		"unicode letter":     "\u00e4k",
		"cyrillic a":         "\u0430k",
		"fullwidth":          "\uff41k",
		"17 characters":      strings.Repeat("a", 17),
		"1 MiB":              strings.Repeat("a", 1<<20),
	} {
		if _, err := apikey.New(newProviderWithPepper(t, randomPepper(t)), apikey.Config{Prefix: prefix}); !errors.Is(err, apikey.ErrInvalidConfig) {
			t.Errorf("%s: apikey.New = %v, want ErrInvalidConfig", name, err)
		}
	}
	for _, ok := range []string{"a", "ak", "0", "09az", strings.Repeat("z", 16)} {
		if _, err := apikey.New(newProviderWithPepper(t, randomPepper(t)), apikey.Config{Prefix: ok}); err != nil {
			t.Errorf("control: prefix %q refused: %v", ok, err)
		}
	}
	if _, err := apikey.New(newProviderWithPepper(t, randomPepper(t)), apikey.Config{}, apikey.Config{}); !errors.Is(err, apikey.ErrInvalidConfig) {
		t.Error("two configs were accepted")
	}
}
