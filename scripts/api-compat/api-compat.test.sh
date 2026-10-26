#!/usr/bin/env bash
# api-compat.test.sh builds two small throwaway modules per case and checks the
# verdict api-compat.sh gives for each change. It needs apidiff and go on PATH
# (or APIDIFF set) and no network: the modules have no dependencies.
#
# Run from anywhere: bash scripts/api-compat/api-compat.test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/api-compat.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

failures=0
cases=0

# write_module DIR: the base API every case starts from.
write_module() {
	local dir="$1"
	mkdir -p "$dir/sub" "$dir/internal/hidden" "$dir/cmd/tool" "$dir/tests/fixture"
	printf 'module example.test/m\n\ngo 1.22\n' >"$dir/go.mod"
	cat >"$dir/m.go" <<'EOF'
package m

// T is a public type.
type T struct{ X int }

// A is a public function.
func A() {}

// Get returns the value.
func (t T) Get() int { return t.X }
EOF
	printf 'package sub\n\n// S is public.\nfunc S() string { return "" }\n' >"$dir/sub/sub.go"
	printf 'package hidden\n\n// H is internal.\nfunc H() {}\n' >"$dir/internal/hidden/h.go"
	printf 'package main\n\nfunc main() {}\n' >"$dir/cmd/tool/main.go"
	printf 'package fixture\n\n// F is a test fixture.\nfunc F() {}\n' >"$dir/tests/fixture/f.go"
}

# run_case NAME WANT_EXIT WANT_TEXT LABELS MUTATE: copy the base to a head,
# apply MUTATE (a shell snippet run in the head), run the script, and check the
# exit code and that its output contains WANT_TEXT.
run_case() {
	local name="$1" want="$2" text="$3" labels="$4" mutate="$5"
	local base="$tmp/$name/base" head="$tmp/$name/head" out got
	cases=$((cases + 1))
	write_module "$base"
	cp -R "$base" "$head"
	(cd "$head" && eval "$mutate")
	set +e
	out="$(PR_LABELS="$labels" GITHUB_ACTIONS=true bash "$script" "$base" "$head" 2>&1)"
	got=$?
	set -e
	if [ "$got" -ne "$want" ]; then
		printf 'FAIL %s: exit %d, want %d\n%s\n' "$name" "$got" "$want" "$out"
		failures=$((failures + 1))
		return
	fi
	if ! printf '%s' "$out" | grep -qF -- "$text"; then
		printf 'FAIL %s: output lacks %q\n%s\n' "$name" "$text" "$out"
		failures=$((failures + 1))
		return
	fi
	printf 'ok   %s\n' "$name"
}

run_case identical 0 "no change in the public API" "" ':'
run_case addition-warns-but-passes 0 "::warning title=Public API grew" "" \
	"printf 'package m\n\nfunc B() {}\n\ntype U struct{}\n' >extra.go"
run_case new-field-is-an-addition 0 "addition" "" \
	"sed -i 's/type T struct{ X int }/type T struct{ X int; Y int }/' m.go"
run_case removal-fails 1 "no breaking label" "" \
	"sed -i '/^func A() {}$/d' m.go"
run_case removal-with-label-passes 0 "acknowledged by the breaking label" $'bug\nbreaking' \
	"sed -i '/^func A() {}$/d' m.go"
run_case lookalike-label-does-not-count 1 "no breaking label" $'not-breaking\nbreaking-ish' \
	"sed -i '/^func A() {}$/d' m.go"
run_case signature-change-fails 1 "Incompatible changes" "" \
	"sed -i 's/^func A() {}$/func A(n int) {}/' m.go"
run_case method-removal-fails 1 "Get" "" \
	"sed -i '/^func (t T) Get/d' m.go"
run_case field-removal-fails 1 "T.X" "" \
	"sed -i 's/type T struct{ X int }/type T struct{}/; s/return t.X/return 0/' m.go"
run_case unneeded-label-warns 0 "Unneeded breaking label" "breaking" ':'
run_case internal-change-is-ignored 0 "no change in the public API" "" \
	"printf 'package hidden\n\nfunc H(n int) {}\n' >internal/hidden/h.go"
run_case tests-and-cmd-are-ignored 0 "no change in the public API" "" \
	"printf 'package fixture\n\nfunc F(n int) {}\n' >tests/fixture/f.go"
run_case new-package-is-an-addition 0 "new package" "" \
	"mkdir extra && printf 'package extra\n\nfunc E() {}\n' >extra/extra.go"
run_case removed-package-fails 1 "package removed" "" \
	"rm -r sub"
run_case a-package-that-does-not-compile-is-not-a-pass 2 "cannot load" "" \
	"printf 'package m\n\nfunc broken( {\n' >broken.go"

# A missing apidiff is a tool error, not a pass.
cases=$((cases + 1))
if APIDIFF=/nonexistent/apidiff bash "$script" "$tmp/identical/base" "$tmp/identical/head" >/dev/null 2>&1; then
	echo "FAIL missing-apidiff: the script passed without a tool"
	failures=$((failures + 1))
else
	got=$?
	if [ "$got" -eq 2 ]; then
		echo "ok   missing-apidiff"
	else
		echo "FAIL missing-apidiff: exit $got, want 2"
		failures=$((failures + 1))
	fi
fi

# Wrong argument count is a usage error.
cases=$((cases + 1))
if bash "$script" only-one >/dev/null 2>&1; then
	echo "FAIL usage: the script passed with one argument"
	failures=$((failures + 1))
else
	echo "ok   usage"
fi

echo "api-compat.test: $((cases - failures))/$cases passed"
[ "$failures" -eq 0 ]
