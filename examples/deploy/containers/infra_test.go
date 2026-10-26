package main

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

func readFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// directives returns the non-comment lines of a file, trimmed.
func directives(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

var secretWord = regexp.MustCompile(`(?i)(secret|password|passwd|token|api[_-]?key|private)`)

// TestContainerfileIsNonRootAndHoldsNoSecrets reads the image definition: the
// default user is not root, nothing in a layer is a key, and no build argument
// or variable carries a credential.
func TestContainerfileIsNonRootAndHoldsNoSecrets(t *testing.T) {
	lines := directives(readFile(t, "Containerfile"))

	var user string
	for _, line := range lines {
		fields := strings.Fields(line)
		switch strings.ToUpper(fields[0]) {
		case "USER":
			user = fields[1]
		case "ENV", "ARG":
			if secretWord.MatchString(line) {
				t.Errorf("%q puts a credential in a layer", line)
			}
		case "ADD":
			t.Errorf("%q: ADD fetches and unpacks; COPY says what it does", line)
		case "COPY":
			for _, f := range fields[1:] {
				if strings.Contains(f, "authcore") || strings.HasSuffix(f, ".pem") || strings.Contains(f, "keys") || f == "." {
					t.Errorf("%q copies key material or the whole context into the image", line)
				}
			}
		case "FROM":
			if strings.HasSuffix(fields[1], ":latest") || (!strings.Contains(fields[1], ":") && fields[1] != "scratch") {
				t.Errorf("%q: the base image is not pinned", line)
			}
		}
	}
	if user == "" || user == "0" || strings.HasPrefix(user, "0:") || user == "root" || strings.HasPrefix(user, "root:") {
		t.Errorf("default user %q: the image runs as root when started without the compose file", user)
	}
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, `ENTRYPOINT ["`) {
		t.Errorf("the last directive %q is not an exec-form ENTRYPOINT", last)
	}
}

// TestComposeDropsPrivilege reads the deployment definition for the settings
// a hardened service carries. It is line based on purpose: the module takes no
// YAML dependency.
func TestComposeDropsPrivilege(t *testing.T) {
	text := readFile(t, "compose.yaml")
	lines := directives(text)
	joined := "\n" + strings.Join(lines, "\n") + "\n"

	for _, want := range []string{"read_only: true", "- ALL", "- no-new-privileges:true", "userns_mode: keep-id"} {
		if !strings.Contains(joined, "\n"+want+"\n") && !strings.Contains(joined, want) {
			t.Errorf("compose.yaml lacks %q", want)
		}
	}
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "privileged:") && !strings.Contains(line, "false"):
			t.Errorf("%q", line)
		case strings.HasPrefix(line, "cap_add"), strings.HasPrefix(line, "ports:"), strings.HasPrefix(line, "devices:"):
			t.Errorf("%q: the probe needs no capability, port or device", line)
		case strings.Contains(line, "network_mode") || strings.HasPrefix(line, "pid:") || strings.HasPrefix(line, "ipc:") || strings.HasPrefix(line, "userns_mode: host"):
			t.Errorf("%q shares a namespace with the host", line)
		case strings.HasPrefix(line, "image:") && (strings.HasSuffix(line, ":latest") || !strings.Contains(strings.TrimPrefix(line, "image:"), ":")):
			t.Errorf("%q: the image is not pinned to a tag", line)
		case strings.Contains(line, "/var/run/docker.sock") || strings.Contains(line, "/run/podman"):
			t.Errorf("%q hands the container control of the engine", line)
		}
	}
	for _, key := range []string{"pids_limit:", "mem_limit:", "healthcheck:"} {
		if !strings.Contains(text, key) {
			t.Errorf("compose.yaml sets no %s", strings.TrimSuffix(key, ":"))
		}
	}
	if !strings.Contains(text, `"/probe", "-check"`) {
		t.Error("the healthcheck does not run the probe, so it cannot tell whether the keys still load")
	}
}

// TestComposeKeepsKeysReadOnlyAndOutOfTheFile checks the volume mount and the
// environment: the keys are mounted read-only from an external volume, and the
// file carries a path, never a value.
func TestComposeKeepsKeysReadOnlyAndOutOfTheFile(t *testing.T) {
	lines := directives(readFile(t, "compose.yaml"))

	var mounts, envs int
	section := ""
	for _, line := range lines {
		if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "-") {
			section = strings.TrimSuffix(line, ":")
			continue
		}
		switch section {
		case "volumes":
			if strings.HasPrefix(line, "- ") && strings.Count(line, ":") >= 2 {
				mounts++
				if !strings.HasSuffix(line, ":ro") {
					t.Errorf("%q is mounted writable", line)
				}
			}
		case "environment":
			envs++
			name, value, _ := strings.Cut(line, ":")
			value = strings.TrimSpace(value)
			if name != "AUTHCORE_KEYS_DIR" || !strings.HasPrefix(value, "/") {
				t.Errorf("%q: the only variable is the path of the keys", line)
			}
		}
	}
	if mounts == 0 || envs == 0 {
		t.Errorf("found %d mounts and %d variables: the test no longer reads the file", mounts, envs)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "external: true") {
		t.Error("the keys volume is not external: down -v would delete it")
	}
}

// TestRecipeIsStrictAndShellcheckClean runs shellcheck when it is installed,
// which it is on the CI runner, and checks the script's own safety flags.
func TestRecipeIsStrictAndShellcheckClean(t *testing.T) {
	script := readFile(t, "recipe.sh")
	if !strings.Contains(script, "set -euo pipefail") {
		t.Error("recipe.sh does not run with set -euo pipefail")
	}
	for _, bad := range []string{"sudo ", "--privileged", "curl ", "wget ", "| sh", "| bash", "eval ", "chmod 777", "chmod -R 777"} {
		if strings.Contains(script, bad) {
			t.Errorf("recipe.sh contains %q", bad)
		}
	}

	path, err := exec.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, path, "--severity=style", "recipe.sh").CombinedOutput(); err != nil {
		t.Errorf("shellcheck: %v\n%s", err, out)
	}
}
