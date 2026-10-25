//go:build unix

package concurrency

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/tests/hostile/keymanager/hostiletest"
)

// Multiple processes: this test binary re-executes itself as the initialisers.

const childEnv = "AUTHCORE_HOSTILE_CHILD"

// TestHostile_Concurrency_childProcess is the body of one initialiser
// process. It only does anything when the parent test started it.
func TestHostile_Concurrency_childProcess(t *testing.T) {
	spec := os.Getenv(childEnv)
	if spec == "" {
		t.Skip("helper process of TestHostile_Concurrency_processesAgreeOnOneSet; nothing to do when run directly")
	}
	parts := strings.Split(spec, "|")
	dir, mode, gate, ready := parts[0], parts[1], parts[2], parts[3]
	if err := os.WriteFile(ready, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(gate); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the gate never opened")
		}
		time.Sleep(time.Millisecond)
	}
	r := hostiletest.Open(t, dir, mode == "load")
	if r.Err != nil {
		fmt.Printf("RESULT err %s\n", strings.ReplaceAll(r.Err.Error(), "\n", " "))
		return
	}
	fmt.Printf("RESULT ok %s %x\n", r.Keys.KeyID(), r.Keys.RefreshSecret())
}

func TestHostile_Concurrency_processesAgreeOnOneSet(t *testing.T) {
	const writers, loaders = 8, 4
	for round := range 3 {
		t.Run(fmt.Sprintf("round%d", round), func(t *testing.T) {
			sb := hostiletest.NewSandbox(t)
			gate := filepath.Join(sb.Root, "gate")
			type child struct {
				cmd  *exec.Cmd
				out  *strings.Builder
				load bool
			}
			var children []child
			for i := range writers + loaders {
				mode := "new"
				if i >= writers {
					mode = "load"
				}
				ready := filepath.Join(sb.Root, fmt.Sprintf("ready-%d", i))
				cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHostile_Concurrency_childProcess$", "-test.count=1")
				cmd.Env = append(os.Environ(), childEnv+"="+strings.Join([]string{sb.Keys, mode, gate, ready}, "|"))
				out := &strings.Builder{}
				cmd.Stdout, cmd.Stderr = out, out
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				children = append(children, child{cmd, out, mode == "load"})
			}
			// Release them together once every one is waiting at the gate.
			for i := range children {
				ready := filepath.Join(sb.Root, fmt.Sprintf("ready-%d", i))
				for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(time.Millisecond) {
					if _, err := os.Stat(ready); err == nil {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("child %d never became ready", i)
					}
				}
			}
			hostiletest.Put(t, gate, nil, 0o600)

			ids := map[string]bool{}
			for i, c := range children {
				if err := c.cmd.Wait(); err != nil {
					t.Fatalf("child %d crashed or failed: %v\n%s", i, err, c.out)
				}
				var result string
				for _, line := range strings.Split(c.out.String(), "\n") {
					if strings.HasPrefix(line, "RESULT ") {
						result = line
					}
				}
				switch {
				case result == "":
					t.Fatalf("child %d printed no result:\n%s", i, c.out)
				case strings.HasPrefix(result, "RESULT err"):
					if !c.load {
						t.Fatalf("writable child %d failed: %s", i, result)
					}
				default:
					ids[strings.TrimPrefix(result, "RESULT ok ")] = true
				}
			}
			if len(ids) != 1 {
				t.Fatalf("processes ended with %d different key sets: %v", len(ids), ids)
			}
			assertCleanFinalState(t, sb.Keys)
		})
	}
}
