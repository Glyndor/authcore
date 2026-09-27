#!/usr/bin/env bash
# Tests for scripts/release-notes.sh, run by the release-notes job in ci.yml.
#
# gh is replaced by a stub that prints a fixture. testdata/release-prs.json is
# a real `gh pr list --state merged --base main --json
# number,mergeCommit,labels,body` response for #458, #450 and #397, captured on
# 2026-09-25, so the tests read the shape gh actually returns. Variants are
# derived from it with jq, each changing one thing.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/release-notes.sh"
fixture="$here/testdata/release-prs.json"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"
cat >"$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$GH_ARGS_LOG"
if [ -n "${GH_FAIL:-}" ]; then
	echo "gh: HTTP 502" >&2
	exit 1
fi
cat "$GH_FIXTURE"
EOF
chmod +x "$work/bin/gh"

pass=0
fail=0
check() { # name, want, got
	if [ "$2" = "$3" ]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		printf 'FAIL %s\n  want: %q\n  got:  %q\n' "$1" "$2" "$3"
	fi
}

# run <fixture> <commit>: sets status, out and err.
run() {
	: >"$work/args"
	out="$(GH_FAIL="${GH_FAIL:-}" GH_FIXTURE="$1" GH_ARGS_LOG="$work/args" PATH="$work/bin:$PATH" \
		bash "$script" "$2" 2>"$work/err")"
	status=$?
	err="$(cat "$work/err")"
}

said() { # fragment: 1 if stderr contains it, else 0
	case "$err" in *"$1"*) echo 1 ;; *) echo 0 ;; esac
}

variant() { # name, jq filter applied to the fixture
	jq "$2" "$fixture" >"$work/$1.json"
	echo "$work/$1.json"
}

commit458=2f5868b8966c595729b34a3e165d94f6e06b3a66
commit450=9b65f6eb5a4d8434f4ff912d26682b055f3666a6

# A release pull request without the breaking label: its body, trailer dropped.
run "$fixture" "$commit458"
body458="$(jq -r '.[] | select(.number == 458) | .body' "$fixture")"
check "non-breaking release exits 0" 0 "$status"
check "non-breaking release starts with the body" "$(head -n 1 <<<"$body458")" "$(head -n 1 <<<"$out")"
check "the DCO trailer is dropped" 0 "$(grep -c '^Signed-off-by:' <<<"$out")"
check "the last line is the last line of text" "$(grep -v '^Signed-off-by:' <<<"$body458" | grep -v '^[[:space:]]*$' | tail -n 1)" "$(tail -n 1 <<<"$out")"
check "the body is not empty" 1 "$([ -n "$(head -n 1 <<<"$body458")" ] && echo 1 || echo 0)"
check "gh is asked for merged pull requests into main" 1 "$(grep -c -- '--state merged --base main' "$work/args")"

# The breaking label with a "## Breaking" section is accepted.
run "$fixture" "$commit450"
check "breaking release with its section exits 0" 0 "$status"
check "breaking release keeps its section" 1 "$(grep -c '^## Breaking: hashing methods' <<<"$out")"

# The same pull request with the section renamed is refused, for that reason.
run "$(variant no-section '(.[] | select(.number == 450) | .body) |= gsub("## Breaking"; "## Changes")')" "$commit450"
check "breaking release without its section exits 1" 1 "$status"
check "and says which rule, naming the pull request" 1 "$(said '#450 is labelled breaking and its body has no "## Breaking" section')"
check "and prints no notes" "" "$out"

# The acceptance pair: the same rename without the label passes.
run "$(variant no-label '(.[] | select(.number == 450)) |= (.body |= gsub("## Breaking"; "## Changes") | .labels |= map(select(.name != "breaking")))')" "$commit450"
check "the same body without the breaking label exits 0" 0 "$status"

# A commit no release pull request merged is refused.
run "$fixture" 0000000000000000000000000000000000000000
check "unknown commit exits 1" 1 "$status"
check "unknown commit names the commit" 1 "$(said 'no merged pull request into main has merge commit 0000000000000000000000000000000000000000')"
check "unknown commit prints no notes" "" "$out"

# An empty body, and a body that is only the trailer, are refused.
run "$(variant empty '(.[] | select(.number == 458) | .body) = ""')" "$commit458"
check "empty body exits 1" 1 "$status"
check "empty body says so" 1 "$(said '#458 has an empty body')"
run "$(variant only-trailer '(.[] | select(.number == 458) | .body) = "Signed-off-by: Jaro-c <75870284+Jaro-c@users.noreply.github.com>\n"')" "$commit458"
check "trailer-only body exits 1" 1 "$status"
check "trailer-only body says it is empty" 1 "$(said '#458 has an empty body')"

# CRLF line endings, as a body edited in the browser can carry, are normalised
# and the trailer is still found.
run "$(variant crlf '(.[] | select(.number == 458) | .body) |= gsub("\n"; "\r\n")')" "$commit458"
check "CRLF body exits 0" 0 "$status"
check "CRLF body loses its carriage returns" 0 "$(grep -c $'\r' <<<"$out")"
check "CRLF body loses its trailer" 0 "$(grep -c '^Signed-off-by:' <<<"$out")"

# A Signed-off-by line inside the text is text, not the trailer.
run "$(variant inner-trailer '(.[] | select(.number == 458) | .body) = "Notes.\nSigned-off-by: someone quoted\nMore notes.\n\nSigned-off-by: Jaro-c <75870284+Jaro-c@users.noreply.github.com>\n"')" "$commit458"
check "an inner Signed-off-by line is kept" "Notes."$'\n'"Signed-off-by: someone quoted"$'\n'"More notes." "$out"

# gh failing is a failure, never an empty set of notes.
GH_FAIL=1 run "$fixture" "$commit458"
check "gh failure exits non-zero" 1 "$([ "$status" -ne 0 ] && echo 1 || echo 0)"
check "gh failure prints no notes" "" "$out"

printf 'passed %d, failed %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
