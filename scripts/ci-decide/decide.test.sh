#!/usr/bin/env bash
# Tests for scripts/ci-decide/decide.sh, run from ci.yml. It builds a throwaway
# repository and asks the script about real diffs.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/decide.sh"
workflows="$here/../../.github/workflows"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0
passed=0

git init -q "$tmp/r"
cd "$tmp/r"
git config user.email t@example.com
git config user.name t
git config commit.gpgsign false
mkdir -p auth/jwt docs examples/modules/jwt
echo a >auth/jwt/jwt.go
echo a >auth/jwt/jwt_test.go
echo a >docs/guide.md
echo a >examples/modules/jwt/main.go
git add -A
git commit -qm base
base="$(git rev-parse HEAD)"

# commit_change FILE... : one commit touching the given files, returns its sha.
commit_change() {
	git checkout -q "$base"
	for f in "$@"; do
		mkdir -p "$(dirname "$f")"
		echo "$RANDOM" >>"$f"
	done
	git add -A
	git commit -qm change
	git rev-parse HEAD
}

# expect WANT EVENT ACTION HEAD INCLUDE [EXCLUDE] [BASE_REF]
expect() {
	local want="$1" event="$2" action="$3" head="$4" include="$5" exclude="${6:-}" base_ref="${7-develop}" got
	got="$(EVENT="$event" ACTION="$action" BASE="$base" BASE_REF="$base_ref" HEAD="$head" GITHUB_OUTPUT=/dev/stdout \
		bash "$script" "$include" "$exclude" 2>/dev/null)"
	if [ "$got" = "run=$want" ]; then
		passed=$((passed + 1))
	else
		printf 'FAIL: want run=%s, got %q (event=%s action=%s base_ref=%s include=%s exclude=%s)\n' \
			"$want" "$got" "$event" "$action" "$base_ref" "$include" "$exclude" >&2
		fail=1
	fi
}

code='^(auth|internal|cmd)/.*\.go$'
notest='_test\.go$'

h_doc="$(commit_change docs/guide.md)"
h_test="$(commit_change auth/jwt/jwt_test.go)"
h_code="$(commit_change auth/jwt/jwt.go)"
h_both="$(commit_change docs/guide.md auth/jwt/jwt.go)"
# Paths git would print quoted: a non-ASCII letter and a space.
h_utf8="$(commit_change "auth/jwt/ñ.go")"
h_space="$(commit_change "auth/jwt/with space.go")"
h_utf8_doc="$(commit_change "docs/ñ.md")"
h_example="$(commit_change examples/modules/jwt/main.go)"
h_hostile="$(commit_change tests/hostile/attack_test.go)"
h_other_test="$(commit_change tests/meta/policy_test.go)"
h_mod="$(commit_change go.mod)"
h_sum="$(commit_change go.sum)"
h_mixed="$(commit_change examples/modules/jwt/main.go auth/jwt/jwt.go)"

expect false pull_request synchronize "$h_doc" "$code" "$notest"
expect false pull_request synchronize "$h_test" "$code" "$notest"
expect true pull_request synchronize "$h_code" "$code" "$notest"
expect true pull_request synchronize "$h_both" "$code" "$notest"
# A relevant file whose name git would quote must still be seen as relevant.
expect true pull_request synchronize "$h_utf8" "$code" "$notest"
expect true pull_request synchronize "$h_space" "$code" "$notest"
# And an irrelevant one with such a name is still irrelevant.
expect false pull_request synchronize "$h_utf8_doc" "$code" "$notest"
# Without an exclude the test file counts.
expect true pull_request synchronize "$h_test" "$code"
# Fail open: other events, label changes, a missing or unreadable range.
expect true push "" "$h_doc" "$code" "$notest"
expect true schedule "" "$h_doc" "$code" "$notest"
expect true workflow_dispatch "" "$h_doc" "$code" "$notest"
expect true pull_request labeled "$h_doc" "$code" "$notest"
expect true pull_request unlabeled "$h_doc" "$code" "$notest"
expect true pull_request synchronize "deadbeef" "$code" "$notest"
expect true pull_request synchronize "" "$code" "$notest"
# An empty diff skips develop; a release into main must run every gate.
expect false pull_request synchronize "$base" "$code" "$notest" develop
expect true pull_request synchronize "$base" "$code" "$notest" main
expect true pull_request synchronize "$h_doc" "$code" "$notest" main
# An empty diff is not evidence that nothing changed when the base is unknown.
expect true pull_request synchronize "$base" "$code" "$notest" ''

# The include pattern is a regular expression, not a prefix.
expect true pull_request synchronize "$h_code" '^auth/' ''
expect false pull_request synchronize "$h_doc" '^auth/' ''

# Use the actual gate patterns: tests alone do not change audit inputs,
# examples alone do not change hostile inputs, and tests/ must stay covered.
for workflow in audit hostile; do
	include="$(awk -F "'" '$1 == "          INCLUDE: " { print $2 }' "$workflows/$workflow.yml")"
	exclude="$(awk -F "'" '$1 == "          EXCLUDE: " { print $2 }' "$workflows/$workflow.yml")"
	expect false pull_request synchronize "$h_test" "$include" "$exclude"
	expect true pull_request synchronize "$h_code" "$include" "$exclude"
	expect true pull_request synchronize "$h_mod" "$include" "$exclude"
	expect true pull_request synchronize "$h_sum" "$include" "$exclude"
	expect true pull_request synchronize "$h_mixed" "$include" "$exclude"
	if [ "$workflow" = audit ]; then
		expect false pull_request synchronize "$h_hostile" "$include" "$exclude"
		expect false pull_request synchronize "$h_other_test" "$include" "$exclude"
	else
		expect false pull_request synchronize "$h_example" "$include" "$exclude"
		expect true pull_request synchronize "$h_hostile" "$include" "$exclude"
		expect true pull_request synchronize "$h_other_test" "$include" "$exclude"
	fi
done

# Exercise each generic workflow loader, including a base without decide.sh.
# The per-leg Examples loader is exercised by examples.test.sh below.
# A stale base script that skips must not switch off a release gate.
git checkout -q "$base"
mkdir -p scripts/ci-decide
cat >scripts/ci-decide/decide.sh <<'SCRIPT'
#!/usr/bin/env bash
printf 'run=false\n' >>"$GITHUB_OUTPUT"
SCRIPT
git add scripts/ci-decide/decide.sh
git commit -qm 'old decision script'
old_base="$(git rev-parse HEAD)"

expect_workflow() {
	local want="$1" base_ref="$2" revision="$3" loader="$4" got
	got="$(EVENT=pull_request ACTION=synchronize BASE_REF="$base_ref" BASE="$revision" HEAD="$revision" \
		RUNNER_TEMP="$tmp" GITHUB_OUTPUT=/dev/stdout INCLUDE="$code" EXCLUDE="$notest" \
		bash "$loader" 2>/dev/null)"
	if [ "$got" = "run=$want" ]; then
		passed=$((passed + 1))
	else
		printf 'FAIL: %s want run=%s, got %q (base_ref=%s revision=%s)\n' \
			"$loader" "$want" "$got" "$base_ref" "$revision" >&2
		fail=1
	fi
}

for workflow in api-compat audit ci containers hostile portability; do
	loader="$tmp/$workflow.sh"
	# Extract the real run block, not a copy of its fallback logic.
	awk '
		/^          script=scripts\/ci-decide\/decide.sh$/ { block=1 }
		block { sub(/^          /, ""); print }
		block && /^bash "\$script"/ { exit }
	' "$workflows/$workflow.yml" >"$loader"
	if [ ! -s "$loader" ]; then
		printf 'FAIL: no decision loader in %s\n' "$workflow" >&2
		exit 1
	fi
	expect_workflow true main "$base" "$loader"
	expect_workflow true develop "$base" "$loader"
	expect_workflow true main "$old_base" "$loader"
	expect_workflow false develop "$old_base" "$loader"
done

if [ "$fail" -ne 0 ]; then
	exit 1
fi
printf 'passed %d, failed 0\n' "$passed"

# Keep the per-leg selector and aggregate tests in the existing CI entry point.
bash "$here/examples.test.sh"
