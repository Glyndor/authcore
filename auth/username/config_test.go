package username

import (
	"errors"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/username/internal/reserved"
)

// modWith builds a Username with the requested Config, using the cheapest
// valid setup. cfg is passed verbatim; the production code is responsible
// for filling defaults and validating bounds.
func modWith(t *testing.T, cfg Config) *Username {
	t.Helper()
	m, err := NewWithConfig(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	return m
}

// ---- AllowReservedNames unblocks a built-in reserved name -------------------

func TestNewWithConfig_allowReservedNamesAreUnblocked(t *testing.T) {
	// "support" is in the built-in reserved list. New(p) refuses it; a
	// deployment that runs a real "support" account needs to be able to
	// register it. AllowReservedNames is the toggle.
	mod := modWith(t, Config{AllowReservedNames: []string{"support"}})

	if _, err := mod.ValidateAndNormalize("support"); err != nil {
		t.Errorf("with AllowReservedNames=[support], 'support' must be accepted, got %v", err)
	}
}

func TestNew_p_rejectsSupportByDefault(t *testing.T) {
	// The negative direction: with no AllowReservedNames override the
	// built-in blocklist still applies. This is what the previous test
	// is supposed to have flipped.
	_, err := newMod(t).ValidateAndNormalize("support")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("New(p) must still reject 'support' by default, got %v", err)
	}
}

// ---- ExtraReservedNames adds to the blocklist --------------------------------

func TestNewWithConfig_extraReservedNamesAreBlocked(t *testing.T) {
	// "founder" is not in the built-in list. Adding it to ExtraReservedNames
	// must cause ValidateAndNormalize to reject it.
	mod := modWith(t, Config{ExtraReservedNames: []string{"founder"}})

	if _, err := mod.ValidateAndNormalize("founder"); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("a name listed in ExtraReservedNames must be rejected, got %v", err)
	}
}

func TestNewWithConfig_extraReservedNamesNormalized(t *testing.T) {
	// The comparison happens after normalize() (lowercase + trim), so the
	// caller can pass names in any case or with surrounding whitespace.
	// "  FOUNDER  " must end up matching "founder" in the lookup set.
	mod := modWith(t, Config{ExtraReservedNames: []string{"  FOUNDER  "}})

	if _, err := mod.ValidateAndNormalize("founder"); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("normalized ExtraReservedNames entry must reject the lowercased input, got %v", err)
	}
}

// ---- MinLength changes the lower bound and reports it in the error ----------

func TestNewWithConfig_minLengthRejectsShortName(t *testing.T) {
	// MinLength: 5 must reject a 4-character name AND report the new
	// floor in the error message ("at least 5 characters").
	mod := modWith(t, Config{MinLength: 5})

	_, err := mod.ValidateAndNormalize("abcd")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("expected ErrInvalidUsername for a 4-character name when MinLength=5, got %v", err)
	}
	if reason := errors.Unwrap(err); reason == nil || !strings.Contains(reason.Error(), "5") {
		t.Errorf("error reason must report the configured MinLength (5), got %v", reason)
	}
}

func TestNewWithConfig_minLengthAcceptsBoundary(t *testing.T) {
	// Exactly the floor must be accepted. The test for "below the floor"
	// would also pass with a buggy "<= instead of <", so the boundary
	// test is what proves it is right.
	mod := modWith(t, Config{MinLength: 5})

	if _, err := mod.ValidateAndNormalize("abcde"); err != nil {
		t.Errorf("a name at exactly MinLength=5 must be accepted, got %v", err)
	}
}

// ---- MaxLength changes the upper bound --------------------------------------

func TestNewWithConfig_maxLengthRejectsLongName(t *testing.T) {
	mod := modWith(t, Config{MaxLength: 5})

	_, err := mod.ValidateAndNormalize(strings.Repeat("a", 6))
	if !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("expected ErrInvalidUsername for a 6-character name when MaxLength=5, got %v", err)
	}
}

// ---- validateConfig refuses bad bounds --------------------------------------

func TestValidateConfig_rejectsMinLengthBelowOne(t *testing.T) {
	err := validateConfig(Config{MinLength: 0})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("MinLength=0 must be refused by validateConfig as ErrInvalidConfig, got %v", err)
	}
}

func TestValidateConfig_rejectsMaxLengthBelowMinLength(t *testing.T) {
	err := validateConfig(Config{MinLength: 10, MaxLength: 5})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("MaxLength below MinLength must be refused by validateConfig, got %v", err)
	}
}

func TestValidateConfig_rejectsOversizedMaxLength(t *testing.T) {
	err := validateConfig(Config{MinLength: 1, MaxLength: upperMaxLength + 1})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("MaxLength above the ceiling must be refused, got %v", err)
	}
}

func TestNewWithConfig_invalidConfigReturnsErrInvalidConfig(t *testing.T) {
	// The same bad config that validateConfig refuses must also be
	// refused by NewWithConfig at construction time, so the failure is
	// loud at startup rather than at first registration.
	_, err := NewWithConfig(fakeProvider{}, Config{MinLength: 10, MaxLength: 5})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("NewWithConfig with contradictory bounds must return ErrInvalidConfig, got %v", err)
	}
}

// ---- reservedSet: Allow wins over built-in and over Extra -------------------

func TestReservedSet_allowOverridesBuiltIn(t *testing.T) {
	set := reservedSet(Config{AllowReservedNames: []string{"support"}})
	if _, ok := set["support"]; ok {
		t.Error("AllowReservedNames must remove 'support' from the reserved set")
	}
	// Spot-check that other built-ins stay reserved.
	if _, ok := set["admin"]; !ok {
		t.Error("AllowReservedNames=[support] must NOT remove 'admin' from the reserved set")
	}
}

func TestReservedSet_extraIsAdded(t *testing.T) {
	set := reservedSet(Config{ExtraReservedNames: []string{"founder"}})
	if _, ok := set["founder"]; !ok {
		t.Error("ExtraReservedNames must add 'founder' to the reserved set")
	}
}

func TestReservedSet_emptyConfigEqualsBuiltIn(t *testing.T) {
	// The zero Config{} must produce the same set as the original
	// reserved.Defaults - this is the additive guarantee.
	got := reservedSet(Config{})
	want := make(map[string]struct{}, len(reserved.Defaults))
	for _, n := range reserved.Defaults {
		want[n] = struct{}{}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("zero Config{} is missing built-in reserved name %q", name)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("zero Config{} added a name %q that is not in reserved.Defaults", name)
		}
	}
}
