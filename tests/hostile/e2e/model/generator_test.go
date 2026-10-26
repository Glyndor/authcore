// Package model checks the modules against a model: a deterministic random
// sequence of operations (issue, verify, rotate, revoke, advance the clock,
// tamper) runs against the real modules and against a few lines of plain Go
// that say what should be accepted. The property is one-sided: the library must
// never accept what the model rejects. The other direction is asserted too, so
// a library that is merely too strict shows up as a model to revisit.
//
// A failure prints its seed. Reproduce one sequence with
//
//	E2E_MODEL_SEED=<seed> go test -race -run <Test> ./tests/hostile/e2e/model/
package model

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	fixedSeeds   = 20
	opsPerSeq    = 100
	logTailLines = 12
)

// rng is splitmix64: tiny, deterministic and identical on every platform.
type rng struct{ state uint64 }

func (r *rng) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// intn returns a number in [0, n).
func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

// pick returns one of the options.
func pick[V any](r *rng, options []V) V { return options[r.intn(len(options))] }

// seeds returns the seeds a model test runs: the one in E2E_MODEL_SEED when set,
// otherwise a fixed range plus one drawn from the clock and printed, so every
// run explores something new and every failure can be replayed.
func seeds(t *testing.T) []uint64 {
	t.Helper()
	if v := os.Getenv("E2E_MODEL_SEED"); v != "" {
		s, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("E2E_MODEL_SEED=%q: %v", v, err)
		}
		return []uint64{s}
	}
	out := make([]uint64, 0, fixedSeeds+1)
	for s := uint64(1); s <= fixedSeeds; s++ {
		out = append(out, s)
	}
	fresh := uint64(time.Now().UnixNano())
	t.Logf("extra seed for this run: %d (E2E_MODEL_SEED=%d to replay)", fresh, fresh)
	return append(out, fresh)
}

// trace remembers the operations of one sequence for the failure message.
type trace struct {
	seed  uint64
	lines []string
}

func (tr *trace) add(format string, args ...any) {
	tr.lines = append(tr.lines, fmt.Sprintf(format, args...))
}

// fail ends the test with the seed, the failing step and the last operations.
func (tr *trace) fail(t *testing.T, format string, args ...any) {
	t.Helper()
	tail := tr.lines
	if len(tail) > logTailLines {
		tail = tail[len(tail)-logTailLines:]
	}
	t.Fatalf("seed %d, step %d: %s\nlast operations:\n  %s", tr.seed, len(tr.lines), fmt.Sprintf(format, args...), strings.Join(tail, "\n  "))
}

// minutes is a virtual duration of n minutes.
func minutes(n int) time.Duration { return time.Duration(n) * time.Minute }
