package phc_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/Glyndor/authcore/auth/password/internal/phc"
)

func TestParseInvalidInputHasBoundedAllocation(t *testing.T) {
	valid := phc.Encode(phc.Params{Memory: phc.MinMemory, Iterations: 1, Parallelism: 1}, make([]byte, 16), make([]byte, 32))
	parts := strings.Split(valid, "$")
	for name, input := range map[string]string{
		"segments":   strings.Repeat("$", 1<<20),
		"parameters": strings.Replace(valid, parts[3], strings.Repeat(",", 1<<20), 1),
		"salt":       strings.Replace(valid, "$"+parts[4]+"$", "$"+strings.Repeat("A", 1<<20)+"$", 1),
		"key":        valid[:len(valid)-len(parts[5])] + strings.Repeat("A", 1<<20),
	} {
		t.Run(name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, _, _, err := phc.Parse(input)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, phc.ErrInvalid) {
				t.Fatalf("Parse = %v, want ErrInvalid", err)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
				t.Fatalf("Parse allocated %d bytes, want <= 65536", allocated)
			}
		})
	}
}

func TestParseAcceptsLargestCanonicalFields(t *testing.T) {
	params := phc.Params{Memory: phc.MaxMemory, Iterations: phc.MaxIterations, Parallelism: 255}
	input := phc.Encode(params, make([]byte, 16), make([]byte, 32))
	got, _, _, err := phc.Parse(input)
	if err != nil || got != params {
		t.Fatalf("Parse = %+v, %v; want %+v, nil", got, err, params)
	}
}
