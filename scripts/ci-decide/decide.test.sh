#!/usr/bin/env bash
# Tests for scripts/ci-decide/decide.sh, run from ci.yml. It builds a throwaway
# repository and asks the script about real diffs.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/decide.sh"
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

# expect WANT EVENT ACTION HEAD INCLUDE [EXCLUDE]
expect() {
	local want="$1" event="$2" action="$3" head="$4" include="$5" exclude="${6:-}" got
	got="$(EVENT="$event" ACTION="$action" BASE="$base" HEAD="$head" GITHUB_OUTPUT=/dev/stdout \
		bash "$script" "$include" "$exclude" 2>/dev/null)"
	if [ "$got" = "run=$want" ]; then
		passed=$((passed + 1))
	else
		printf 'FAIL: want run=%s, got %q (event=%s action=%s include=%s exclude=%s)\n' \
			"$want" "$got" "$event" "$action" "$include" "$exclude" >&2
		fail=1
	fi
}

code='^(auth|internal|cmd)/.*\.go$'
notest='_test\.go$'

h_doc="$(commit_change docs/guide.md)"
h_test="$(commit_change auth/jwt/jwt_test.go)"
h_code="$(commit_change auth/jwt/jwt.go)"
h_both="$(commit_change docs/guide.md auth/jwt/jwt.go)"

expect false pull_request synchronize "$h_doc" "$code" "$notest"
expect false pull_request synchronize "$h_test" "$code" "$notest"
expect true pull_request synchronize "$h_code" "$code" "$notest"
expect true pull_request synchronize "$h_both" "$code" "$notest"
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
# An empty diff is not evidence that nothing changed.
expect true pull_request synchronize "$base" "$code" "$notest"

# The include pattern is a regular expression, not a prefix.
expect true pull_request synchronize "$h_code" '^auth/' ''
expect false pull_request synchronize "$h_doc" '^auth/' ''

if [ "$fail" -ne 0 ]; then
	exit 1
fi
printf 'passed %d, failed 0\n' "$passed"
