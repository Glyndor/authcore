package credential_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Glyndor/authcore"
	"github.com/Glyndor/authcore/auth/credential"
)

// Class: clock offsets and zones. The module reads the time through the
// Timezone the provider reports and compares it with the issue time the caller
// stores, so the answer must depend on the two instants and on nothing else:
// not on the zone either is written in, not on a monotonic reading, not on the
// zone the host or the provider is in.

// zonedProvider is a provider whose Config reports the given Timezone.
type zonedProvider struct {
	provider
	loc *time.Location
}

func (z zonedProvider) Config() authcore.Config {
	cfg := authcore.DefaultConfig()
	cfg.Timezone = z.loc
	return cfg
}

func newZoned(t testing.TB, loc *time.Location, ttl time.Duration) *credential.Credential {
	t.Helper()
	p := zonedProvider{provider: newProviderWithPepper(t, randomPepper(t)), loc: loc}
	m, err := credential.New(p, credential.Config{TTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func zones(t testing.TB) map[string]*time.Location {
	t.Helper()
	out := map[string]*time.Location{
		"UTC": time.UTC, "fixed +14:00": time.FixedZone("kiritimati", 14*3600),
		"fixed -12:00": time.FixedZone("baker", -12*3600), "fixed +05:45": time.FixedZone("kathmandu", 5*3600+45*60),
		"fixed +00:00 named": time.FixedZone("GMT", 0), "nil": nil,
	}
	for _, name := range []string{"Asia/Kolkata", "America/St_Johns", "Pacific/Chatham", "Australia/Lord_Howe", "Europe/London"} {
		if loc, err := time.LoadLocation(name); err == nil {
			out[name] = loc
		}
	}
	return out
}

// The same four instants, relative to now, in every zone of the provider and in
// every spelling of the issue time, give the same four answers.
func TestHostile_Clock_theAnswerDoesNotDependOnAnyZone(t *testing.T) {
	const ttl = time.Hour
	for provZone, loc := range zones(t) {
		m := newZoned(t, loc, ttl)
		issued, _ := m.Issue("reset", "alice")
		now := time.Now()
		for stampZone, sloc := range zones(t) {
			if sloc == nil {
				continue
			}
			for name, tc := range map[string]struct {
				at   time.Time
				want error
			}{
				"fresh":           {now.Add(-5 * time.Second), nil},
				"inside the ttl":  {now.Add(-ttl + 10*time.Second), nil},
				"past the ttl":    {now.Add(-ttl - 10*time.Second), credential.ErrExpired},
				"skew accepted":   {now.Add(40 * time.Second), nil},
				"skew exceeded":   {now.Add(80 * time.Second), credential.ErrExpired},
				"no monotonic":    {now.Round(0).Add(-time.Minute), nil},
				"day-old no mono": {now.Round(0).Add(-24 * time.Hour), credential.ErrExpired},
			} {
				at := tc.at.In(sloc)
				err := m.Verify("reset", "alice", issued.Token, issued.Hash, at)
				if !errors.Is(err, tc.want) {
					t.Errorf("provider %s, stamp %s, %s: %v, want %v", provZone, stampZone, name, err, tc.want)
				}
			}
		}
	}
}

// Wall-clock arithmetic, not instants: an issue time built from the same
// "12:00" in different zones is a different instant and must be judged as one.
func TestHostile_Clock_sameWallTimeInDifferentZonesIsADifferentInstant(t *testing.T) {
	m := newZoned(t, time.UTC, 2*time.Hour)
	issued, _ := m.Issue("reset", "alice")
	n := time.Now().UTC()
	wall := time.Date(n.Year(), n.Month(), n.Day(), n.Hour(), n.Minute(), n.Second(), 0, time.UTC)
	for name, tc := range map[string]struct {
		zone *time.Location
		want error
	}{
		"same zone":           {time.UTC, nil},
		"five hours east":     {time.FixedZone("e", 5*3600), credential.ErrExpired},
		"five hours west":     {time.FixedZone("w", -5*3600), credential.ErrExpired},
		"thirty minutes east": {time.FixedZone("half", 30*60), nil},
	} {
		at := time.Date(wall.Year(), wall.Month(), wall.Day(), wall.Hour(), wall.Minute(), wall.Second(), 0, tc.zone)
		err := m.Verify("reset", "alice", issued.Token, issued.Hash, at)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

// The extremes of what a caller can pass: the answer is expiry, never a panic
// and never success, whatever the arithmetic would overflow to.
func TestHostile_Clock_extremeIssueTimesAreExpiredNotWrapped(t *testing.T) {
	for name, ttlLimit := range map[string]time.Duration{"1ns": time.Nanosecond, "1h": time.Hour, "24h": 24 * time.Hour} {
		m := newZoned(t, time.UTC, ttlLimit)
		issued, _ := m.Issue("reset", "alice")
		for stamp, at := range map[string]time.Time{
			"zero":          {},
			"min unix":      time.Unix(-1<<63+1, 0),
			"max unix":      time.Unix(1<<63-1, 999999999),
			"year 292277k":  time.Date(292277026596, 12, 4, 15, 30, 7, 0, time.UTC),
			"year -292277k": time.Date(-292277022657, 1, 27, 8, 29, 52, 0, time.UTC),
			"max duration":  time.Now().Add(1<<63 - 1),
			"min duration":  time.Now().Add(-1 << 63),
			"before epoch":  time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC),
		} {
			if err := m.Verify("reset", "alice", issued.Token, issued.Hash, at); !errors.Is(err, credential.ErrExpired) {
				t.Errorf("ttl %s, issued at %s: %v, want ErrExpired", name, stamp, err)
			}
		}
	}
}
