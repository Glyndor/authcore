package tokenid

import (
	"encoding/base64"
	"regexp"
	"testing"
	"time"
)

// uuidV7Shape is RFC 9562 section 5.7 written apart from IsUUIDv7.
var uuidV7Shape = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

// TestNewRID pins the contract of NewRID: it returns a base64 raw
// URL-encoded value whose decoded length is exactly 16 bytes, and two calls in
// the same nanosecond produce distinct values.
func TestNewRID(t *testing.T) {
	first, err := NewRID()
	if err != nil {
		t.Fatalf("NewRID() first error = %v", err)
	}
	second, err := NewRID()
	if err != nil {
		t.Fatalf("NewRID() second error = %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("decode first RID: %v", err)
	}
	if len(decoded) != 16 {
		t.Errorf("decoded RID length = %d, want 16", len(decoded))
	}
	if first == second {
		t.Errorf("two consecutive NewRID() calls returned the same value %q", first)
	}
}

func TestNewJTI_isUUIDv7WithTheTimestamp(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_123)
	a, err := NewJTI(now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewJTI(now)
	if err != nil {
		t.Fatal(err)
	}
	if !uuidV7Shape.MatchString(a) || !IsUUIDv7(a) {
		t.Fatalf("NewJTI = %q, not a UUID v7", a)
	}
	if a == b {
		t.Fatalf("two NewJTI calls returned %q", a)
	}
	if a[:13] != "018bcfe5-687b" {
		t.Fatalf("timestamp prefix = %q, want 018bcfe5-687b", a[:13])
	}
}

func TestIsUUIDv7(t *testing.T) {
	for in, want := range map[string]bool{
		"":                                     false,
		"018f0c8e-9b2a-7c3a-8b1e-1234567890ab": true,
		"018F0C8E-9B2A-7C3A-8B1E-1234567890AB": true,
		"018f0c8e-9b2a-7c3a-cb1e-1234567890ab": false, // variant c
		"018f0c8e-9b2a-4c3a-8b1e-1234567890ab": false, // version 4
		"018f0c8e9-b2a-7c3a-8b1e-1234567890ab": false, // dash moved
		"018f0c8e-9b2a-7c3a-8b1e-1234567890ag": false, // non-hex
		"018f0c8e-9b2a-7c3a-8b1e-1234567890a":  false, // short
		"018f0c8e09b2a07c3a08b1e01234567890ab": false, // no dashes
	} {
		if got := IsUUIDv7(in); got != want || got != uuidV7Shape.MatchString(in) {
			t.Errorf("IsUUIDv7(%q) = %v, want %v", in, got, want)
		}
	}
}
