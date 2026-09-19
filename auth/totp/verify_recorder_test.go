package totp

// Recorder-backed Verify tests. The reference in-memory recorder lives in
// this file because it is only needed here, and a private context key is
// used so a test can assert the recorder received the same context the
// caller passed to Verify.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/clock"
)

// ---- reference in-memory recorder ------------------------------------------

// memoryRecorder is the reference StepRecorder used by the Verify tests.
// It stores a single step in a uint64, refuses anything not strictly
// greater than the stored value with ErrCodeReused, and counts how many
// times RecordIfNewer was called. The mutex makes the compare-and-advance
// atomic for tests running under -race, which is the property the
// concurrent submissions test needs in the absence of a real database.
type memoryRecorder struct {
	mu       sync.Mutex
	step     uint64
	calls    int32
	lastCtx  context.Context
	sawValue any
}

func (r *memoryRecorder) RecordIfNewer(ctx context.Context, step uint64) error {
	atomic.AddInt32(&r.calls, 1)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastCtx = ctx
	if v := ctx.Value(recorderCtxTestKey); v != nil {
		r.sawValue = v
	}
	if step <= r.step {
		return ErrCodeReused
	}
	r.step = step
	return nil
}

func (r *memoryRecorder) callCount() int32 { return atomic.LoadInt32(&r.calls) }

// recorderCtxTestKey is the private key the context-propagation test
// uses to put a marker value into a context and assert the recorder
// received it. The recorder is package-private so the key lives here
// next to its only reader.
type ctxKey struct{ name string }

var recorderCtxTestKey = ctxKey{name: "recorder-test"}

// ---- helpers ---------------------------------------------------------------

// newCodeForNow mints a code for the current fixed clock at baseTime and
// returns the matching step. Tests that need a known-good code without
// depending on a particular secret generate one through the same path
// the production code uses.
func newCodeForNow(tb testing.TB, mod *TOTP, baseTime int64) (string, uint64) {
	tb.Helper()
	key, err := decodeSecret(rfcSecretB32)
	if err != nil {
		tb.Fatalf("decodeSecret: %v", err)
	}
	step := uint64(baseTime) / timeStep
	mod.clock = clock.Fixed(time.Unix(baseTime, 0).UTC())
	return generateTOTP(key, step), step
}

// TestVerifyRequiresRecorder pins the contract that a nil recorder is a
// programming error and is refused with ErrStepRecorderRequired before
// any other check runs.
func TestVerifyRequiresRecorder(t *testing.T) {
	mod := newTOTP(t)
	code, _ := newCodeForNow(t, mod, 240)

	err := mod.Verify(context.Background(), rfcSecretB32, code, nil)
	if !errors.Is(err, ErrStepRecorderRequired) {
		t.Fatalf("Verify with nil recorder returned %v, want ErrStepRecorderRequired", err)
	}
}

// TestVerifyHonoursCancelledContext pins that ctx.Err() is checked before
// anything else and the recorder is not called when the context is
// already cancelled. errors.Is(err, context.Canceled) must hold so
// callers can branch on the standard sentinel.
func TestVerifyHonoursCancelledContext(t *testing.T) {
	mod := newTOTP(t)
	code, _ := newCodeForNow(t, mod, 270)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := &memoryRecorder{}

	err := mod.Verify(ctx, rfcSecretB32, code, rec)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Verify with cancelled context returned %v, want context.Canceled", err)
	}
	if got := rec.callCount(); got != 0 {
		t.Errorf("recorder call count = %d, want 0 (context cancelled before record)", got)
	}
}

// TestVerifyDoesNotRecordRejectedCodes pins that a code VerifyStep
// refuses never reaches the recorder. The recorder's call count must
// stay at 0 for each shape of refusal: malformed code, invalid secret,
// wrong code. A code shape just inside the limit (six digits that
// decode to a valid secret but do not match any window) sits next to
// the malformed inputs as the "almost accepted" boundary.
func TestVerifyDoesNotRecordRejectedCodes(t *testing.T) {
	mod := newTOTP(t)
	const baseTime int64 = 300
	newCodeForNow(t, mod, baseTime) // pin clock to a known value

	cases := []struct {
		name   string
		secret string
		code   string
		want   error
	}{
		{"malformed code: too short", rfcSecretB32, "12345", ErrMalformedCode},
		{"malformed code: letters", rfcSecretB32, "abcdef", ErrMalformedCode},
		{"invalid secret: empty", "", "123456", ErrInvalidSecret},
		{"invalid secret: too short", "MZXW6YTB", "123456", ErrInvalidSecret},
		{"invalid code: six digits no match", rfcSecretB32, "000000", ErrInvalidCode},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &memoryRecorder{}
			err := mod.Verify(context.Background(), c.secret, c.code, rec)
			if !errors.Is(err, c.want) {
				t.Errorf("Verify returned %v, want %v", err, c.want)
			}
			if got := rec.callCount(); got != 0 {
				t.Errorf("recorder call count = %d, want 0 (rejected before record)", got)
			}
		})
	}
}

// TestVerifyRecordsTheMatchedStep pins that a valid code returns nil,
// the recorder was called exactly once, and the recorded step equals
// the step VerifyStep returns for that code. The recorder's stored
// step is read back to confirm the contract end to end.
func TestVerifyRecordsTheMatchedStep(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	code, wantStep := newCodeForNow(t, mod, 330)
	rec := &memoryRecorder{}

	if err := mod.Verify(context.Background(), rfcSecretB32, code, rec); err != nil {
		t.Fatalf("Verify returned %v, want nil", err)
	}
	if got := rec.callCount(); got != 1 {
		t.Errorf("recorder call count = %d, want 1", got)
	}
	rec.mu.Lock()
	got := rec.step
	rec.mu.Unlock()
	if got != wantStep {
		t.Errorf("recorder stored step = %d, want %d", got, wantStep)
	}
}

// TestVerifyReportsReuseFromTheRecorder pins the recorder's ErrCodeReused
// is surfaced as ErrCodeReused on Verify. The same valid code submitted
// twice with one recorder: the first call records and returns nil, the
// second call sees the stored step and returns an error that satisfies
// errors.Is(err, ErrCodeReused).
func TestVerifyReportsReuseFromTheRecorder(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	code, _ := newCodeForNow(t, mod, 360)
	rec := &memoryRecorder{}

	if err := mod.Verify(context.Background(), rfcSecretB32, code, rec); err != nil {
		t.Fatalf("first Verify returned %v, want nil", err)
	}
	err := mod.Verify(context.Background(), rfcSecretB32, code, rec)
	if !errors.Is(err, ErrCodeReused) {
		t.Fatalf("second Verify returned %v, want ErrCodeReused", err)
	}
	if got := rec.callCount(); got != 2 {
		t.Errorf("recorder call count = %d, want 2", got)
	}
}

// TestVerifyWrapsOtherRecorderErrors pins that any recorder error that is
// not ErrCodeReused is wrapped with "totp: record step:" so the recorder
// signal still reaches the caller but is distinguishable from a reuse
// refusal. errors.Is(err, errBoom) must hold; errors.Is(err,
// ErrCodeReused) must not; the message must contain the prefix.
func TestVerifyWrapsOtherRecorderErrors(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	code, _ := newCodeForNow(t, mod, 390)
	errBoom := errors.New("connection refused")
	rec := &boomRecorder{err: errBoom}

	err := mod.Verify(context.Background(), rfcSecretB32, code, rec)
	if err == nil {
		t.Fatal("Verify returned nil, want an error")
	}
	if !errors.Is(err, errBoom) {
		t.Errorf("errors.Is(err, errBoom) = false, want true (err=%v)", err)
	}
	if errors.Is(err, ErrCodeReused) {
		t.Errorf("errors.Is(err, ErrCodeReused) = true, want false (err=%v)", err)
	}
	if msg := err.Error(); !contains(msg, "totp: record step") {
		t.Errorf("error message %q does not contain %q", msg, "totp: record step")
	}
}

// boomRecorder is a StepRecorder that returns a fixed error on every
// call. It is the only way the wrap-with-prefix branch gets exercised
// without a real database.
type boomRecorder struct{ err error }

func (b *boomRecorder) RecordIfNewer(ctx context.Context, step uint64) error {
	return b.err
}

// contains reports whether substr appears anywhere in s. Avoids pulling
// strings into this file just for one substring check.
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestVerifyConcurrentSubmissionsAcceptOnce is the proof that the
// recorder-backed Verify actually closes the read-verify-write race the
// old API left open. 32 goroutines behind a start barrier submit the
// same valid code with one shared recorder; exactly one returns nil
// and the other 31 return ErrCodeReused. The recorder's own mutex
// implements the atomic compare-and-advance; without it, two
// goroutines could both read the old step, both call Verify, and both
// record. The test pins the contract; the contract pins the
// implementation.
func TestVerifyConcurrentSubmissionsAcceptOnce(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	code, _ := newCodeForNow(t, mod, 420)
	rec := &memoryRecorder{}

	const n = 32
	start := make(chan struct{})
	results := make(chan error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- mod.Verify(context.Background(), rfcSecretB32, code, rec)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var ok, reused, other int
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrCodeReused):
			reused++
		default:
			other++
		}
	}
	if ok != 1 {
		t.Errorf("accepted = %d, want 1", ok)
	}
	if reused != n-1 {
		t.Errorf("ErrCodeReused = %d, want %d", reused, n-1)
	}
	if other != 0 {
		t.Errorf("unexpected other errors = %d", other)
	}
}

// TestVerifyPassesContextThrough pins that the context Verify receives
// is the one handed to RecordIfNewer. A private context key carries a
// marker value; the recorder reads it back and the test compares.
func TestVerifyPassesContextThrough(t *testing.T) {
	mod := newTOTP(t, Config{SkewSteps: Int(0)})
	code, _ := newCodeForNow(t, mod, 450)
	rec := &memoryRecorder{}

	want := "marker-1234"
	ctx := context.WithValue(context.Background(), recorderCtxTestKey, want)

	if err := mod.Verify(ctx, rfcSecretB32, code, rec); err != nil {
		t.Fatalf("Verify returned %v, want nil", err)
	}
	rec.mu.Lock()
	got := rec.sawValue
	rec.mu.Unlock()
	if got != want {
		t.Errorf("recorder saw context value %v, want %q", got, want)
	}
}
