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
git config diff.renames true
mkdir -p auth/jwt/helper docs examples/modules/jwt
echo a >auth/jwt/jwt.go
echo a >auth/jwt/jwt_test.go
printf 'package jwt\nfunc Token() {}\n' >auth/jwt/token.go
printf 'package helper\nfunc Exported() {}\n' >auth/jwt/helper/value.go
printf 'package root\n' >root.go
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

# commit_rename OLD NEW : a pure rename, with detection enabled in the fixture.
commit_rename() {
	git checkout -q "$base"
	mkdir -p "$(dirname "$2")"
	git mv "$1" "$2"
	git commit -qm rename
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
h_rename="$(commit_rename auth/jwt/token.go auth/jwt/token.txt)"
h_move_out="$(commit_rename auth/jwt/token.go docs/token.txt)"
h_root_move="$(commit_rename root.go docs/root.txt)"
h_move_excluded="$(commit_rename auth/jwt/token.go auth/jwt/token_test.go)"
h_move_in="$(commit_rename docs/guide.md auth/jwt/moved.go)"

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
# Removing a relevant origin must run, even with an irrelevant/excluded target.
expect true pull_request synchronize "$h_rename" "$code" "$notest"
expect true pull_request synchronize "$h_move_out" "$code" "$notest"
expect true pull_request synchronize "$h_move_excluded" "$code" "$notest"
expect true pull_request synchronize "$h_root_move" '\.go$' "$notest"
# The destination must still count when only the destination is relevant.
expect true pull_request synchronize "$h_move_in" "$code" "$notest"

# Read all six real generic gate filters, including their distinct exclusions.
for workflow in api-compat audit ci containers hostile portability; do
	include="$(awk -F "'" '$1 == "          INCLUDE: " { print $2 }' "$workflows/$workflow.yml")"
	exclude="$(awk -F "'" '$1 == "          EXCLUDE: " { print $2 }' "$workflows/$workflow.yml")"
	for head in "$h_rename" "$h_move_out" "$h_root_move" "$h_move_excluded" "$h_move_in"; do
		expect true pull_request synchronize "$head" "$include" "$exclude"
	done
done

# The API comparator includes public auth packages at every depth, but excludes
# whole internal/tests/examples/cmd components and test source files.
include="$(awk -F "'" '$1 == "          INCLUDE: " { print $2 }' "$workflows/api-compat.yml")"
exclude="$(awk -F "'" '$1 == "          EXCLUDE: " { print $2 }' "$workflows/api-compat.yml")"
for head in "$h_code" "$h_root_move" "$h_mod" "$h_sum"; do
	expect true pull_request synchronize "$head" "$include" "$exclude"
done
for file in scripts/api-compat/api-compat.sh .github/workflows/api-compat.yml; do
	expect true pull_request synchronize "$(commit_change "$file")" "$include" "$exclude"
done
expect false pull_request synchronize "$h_doc" "$include" "$exclude"
expect false pull_request synchronize "$h_test" "$include" "$exclude"
for file in auth/new/subpkg/value.go auth/new/subpkg/deeper/value.go auth/jwt/helper/value.go \
	auth/internalized/subpkg/value.go auth/jwt/tests_helpers/value.go; do
	expect true pull_request synchronize "$(commit_change "$file")" "$include" "$exclude"
done
# A removal in an existing public subpackage must also activate the comparison.
git checkout -q "$base"
printf 'package helper\n' >auth/jwt/helper/value.go
git add auth/jwt/helper/value.go
git commit -qm 'remove nested public symbol'
expect true pull_request synchronize "$(git rev-parse HEAD)" "$include" "$exclude"
for file in auth/jwt/helper/value_test.go auth/jwt/internal/value.go auth/internal/helper/value.go \
	auth/jwt/helper/internal/deeper/value.go auth/jwt/tests/value.go auth/tests/helper/value.go \
	auth/jwt/examples/value.go auth/examples/helper/value.go auth/jwt/cmd/value.go \
	auth/cmd/helper/value.go internal/value.go tests/value.go examples/value.go cmd/value.go; do
	expect false pull_request synchronize "$(commit_change "$file")" "$include" "$exclude"
done

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

# The shared meta decision exposes two independent answers. Read the real
# filters and loader so a workflow-only regression cannot hide behind copies.
meta_job="$tmp/meta-job.yml"
awk '
	/^  decide-meta:$/ { block=1; next }
	block && /^  [^ ]/ { exit }
	block { print }
' "$workflows/ci.yml" >"$meta_job"
pins_include="$(awk -F "'" '$1 == "          PINS_INCLUDE: " { print $2 }' "$meta_job")"
notes_include="$(awk -F "'" '$1 == "          NOTES_INCLUDE: " { print $2 }' "$meta_job")"
tests_include="$(awk -F "'" '$1 == "          TESTS_INCLUDE: " { print $2 }' "$meta_job")"
meta_loader="$tmp/meta-loader.sh"
awk '
	/^        run: \|$/ { block=1; next }
	block && /^          / { sub(/^          /, ""); print; next }
	block { exit }
' "$meta_job" >"$meta_loader"
if [ ! -s "$meta_loader" ] || [ -z "$pins_include" ] || [ -z "$notes_include" ] || [ -z "$tests_include" ]; then
	printf 'FAIL: missing meta loader or filters\n' >&2
	exit 1
fi

# Check the Actions boundary as well as the shell, including named emitters.
# shellcheck disable=SC2016
for binding in '      pins: ${{ steps.decide.outputs.pins }}' \
	'      notes: ${{ steps.decide.outputs.notes }}' \
	"        if: steps.decide.outputs.tests == 'true'"; do
	if grep -qxF "$binding" "$meta_job"; then
		passed=$((passed + 1))
	else
		printf 'FAIL meta wiring: missing %s\n' "$binding" >&2
		fail=1
	fi
done
for job in pin-policy release-notes; do
	awk -v job="$job" '
		$0 == "  " job ":" { block=1; next }
		block && /^  [^ ]/ { exit }
		block { print }
	' "$workflows/ci.yml" >"$tmp/consumer.yml"
	output=pins
	[ "$job" != release-notes ] || output=notes
	if grep -qxF '    needs: decide-meta' "$tmp/consumer.yml" &&
		grep -qxF "    if: needs.decide-meta.outputs.$output == 'true'" "$tmp/consumer.yml"; then
		passed=$((passed + 1))
	else
		printf 'FAIL meta consumer: %s must depend on its named output\n' "$job" >&2
		fail=1
	fi
done

# Install the current generic selector only in the trusted fixture commit.
git checkout -q "$base"
mkdir -p scripts/ci-decide .github/workflows scripts/release-notes
cp "$script" scripts/ci-decide/decide.sh
printf 'base\n' >.github/workflows/release.yml
printf 'base\n' >scripts/release-notes/release-notes.sh
git add -A
git commit -qm 'trusted meta selector'
meta_base="$(git rev-parse HEAD)"

# expect_meta PINS NOTES TESTS HEAD [BRANCH] [EVENT] [ACTION] [BASE]
expect_meta() {
	local pins="$1" notes="$2" tests="$3" head="$4" branch="${5-develop}"
	local event="${6-pull_request}" action="${7-synchronize}" revision="${8-$meta_base}" got want
	want="$(printf 'pins=%s\nnotes=%s\ntests=%s' "$pins" "$notes" "$tests")"
	: >"$tmp/meta.out"
	if EVENT="$event" ACTION="$action" BASE_REF="$branch" BASE="$revision" HEAD="$head" \
		RUNNER_TEMP="$tmp" GITHUB_OUTPUT="$tmp/meta.out" PINS_INCLUDE="$pins_include" \
		NOTES_INCLUDE="$notes_include" TESTS_INCLUDE="$tests_include" EXCLUDE='' \
		bash -e -o pipefail "$meta_loader" >/dev/null 2>&1 && got="$(cat "$tmp/meta.out")" && [ "$got" = "$want" ]; then
		passed=$((passed + 1))
	else
		printf 'FAIL meta: want %q, got %q (head=%s branch=%s event=%s action=%s base=%s)\n' \
			"$want" "$(cat "$tmp/meta.out")" "$head" "$branch" "$event" "$action" "$revision" >&2
		fail=1
	fi
}

for file in .github/workflows/audit.yml .github/workflows/nested/action.yml; do
	expect_meta true false true "$(commit_change "$file")"
done
for file in .github/workflows/ci.yml .github/workflows/release.yml; do
	expect_meta true true true "$(commit_change "$file")"
done
expect_meta true false false "$(commit_change .github/dependabot.yml)"
for file in scripts/release-notes/release-notes.sh scripts/release-notes/release-notes.test.sh \
	'scripts/release-notes/ñ with space.sh'; do
	expect_meta false true false "$(commit_change "$file")"
done
expect_meta false false true "$(commit_change scripts/ci-decide/decide.sh)"
expect_meta false false true "$(commit_change scripts/ci-decide/decide.test.sh)"
expect_meta true true false "$(commit_change .github/dependabot.yml scripts/release-notes/release-notes.sh)"
for file in docs/guide.md auth/jwt/jwt.go .github/dependabot.yml.bak .github/workflows-old/ci.yml \
	scripts/release-notes-old/test.sh scripts/ci-decide-old/test.sh x/.github/workflows/ci.yml; do
	expect_meta false false false "$(commit_change "$file")"
done
expect_meta false false false "$meta_base"
expect_meta true true true "$h_doc" main
expect_meta true true true "$meta_base" main
expect_meta true true true "$h_doc" develop push
expect_meta true true true "$h_doc" develop pull_request labeled
expect_meta true true true "$h_doc" develop pull_request unlabeled
expect_meta true true true deadbeef
expect_meta true true true ''
# Deletions and rename origins must retain their relevant answers.
for file in .github/workflows/release.yml scripts/release-notes/release-notes.sh; do
	git checkout -q "$meta_base"
	git mv "$file" docs/moved.txt
	git commit -qm 'move meta input out'
	pins=true tests=true
	[ "$file" != scripts/release-notes/release-notes.sh ] || { pins=false; tests=false; }
	expect_meta "$pins" true "$tests" "$(git rev-parse HEAD)"
	git checkout -q "$meta_base"
	git rm -q "$file"
	git commit -qm 'delete meta input'
	expect_meta "$pins" true "$tests" "$(git rev-parse HEAD)"
done
# Candidate code cannot replace a trusted decision. The main override also
# precedes absent/old scripts; malformed or failing emitters must fail open.
git checkout -q "$meta_base"
printf 'touch "%s/candidate-ran"\nexit 1\n' "$tmp" >scripts/ci-decide/decide.sh
expect_meta false false false "$h_doc"
if [ -e "$tmp/candidate-ran" ]; then
	printf 'FAIL meta executed the candidate selector\n' >&2
	fail=1
else
	passed=$((passed + 1))
fi
git checkout -q -- scripts/ci-decide/decide.sh
expect_meta true true true "$h_doc" develop pull_request synchronize "$base"
expect_meta true true true "$h_doc" main pull_request synchronize "$base"
expect_meta false false false "$h_doc" develop pull_request synchronize "$old_base"
expect_meta true true true "$h_doc" main pull_request synchronize "$old_base"
while IFS= read -r body; do
	git checkout -q "$meta_base"
	printf '#!/usr/bin/env bash\n%s\n' "$body" >scripts/ci-decide/decide.sh
	git add scripts/ci-decide/decide.sh
	git commit -qm 'broken meta emitter'
	expect_meta true true true "$h_doc" develop pull_request synchronize "$(git rev-parse HEAD)"
done <<'CASES'
exit 1
printf 'garbage\n'
true
printf 'run=false\n'; exit 1
printf 'run=false\nrun=false\n'
CASES

if [ "$fail" -ne 0 ]; then
	exit 1
fi
printf 'passed %d, failed 0\n' "$passed"

# Keep the per-leg selector and aggregate tests in the existing CI entry point,
# along with the API gate's verdict and Actions bindings.
bash "$here/examples.test.sh"
bash "$here/api-compat.test.sh"
