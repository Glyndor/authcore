#!/usr/bin/env bash
# Decides whether the jobs behind it have anything to look at.
#
#   decide.sh INCLUDE [EXCLUDE]
#
# INCLUDE and EXCLUDE are extended regular expressions over the paths a pull
# request changes. The answer is "run" when at least one changed path matches
# INCLUDE and does not match EXCLUDE. It writes run=true or run=false to
# $GITHUB_OUTPUT (standard output when that is unset).
#
# It fails open: on any event other than a pull request, on a label change, and
# whenever it cannot read the diff, the answer is "run". A wrong "skip" would
# let a pull request merge without a gate having looked at it; a wrong "run"
# costs only minutes.
#
# Environment: EVENT (github.event_name), ACTION (github.event.action), BASE and
# HEAD (the pull request's base and head commits).
set -euo pipefail

include="${1:?usage: decide.sh INCLUDE [EXCLUDE]}"
exclude="${2:-}"
out="${GITHUB_OUTPUT:-/dev/stdout}"

say() {
	printf 'run=%s\n' "$1" >>"$out"
	printf 'decide: run=%s (%s)\n' "$1" "$2" >&2
}

if [ "${EVENT:-}" != "pull_request" ]; then
	say true "event ${EVENT:-unset} always runs"
	exit 0
fi
case "${ACTION:-}" in
labeled | unlabeled)
	say true "label change"
	exit 0
	;;
esac
if [ -z "${BASE:-}" ] || [ -z "${HEAD:-}" ]; then
	say true "no base or head commit"
	exit 0
fi
if ! files="$(git diff --name-only "${BASE}...${HEAD}" 2>/dev/null)"; then
	say true "could not read the diff"
	exit 0
fi
if [ -z "$files" ]; then
	say true "empty diff"
	exit 0
fi

matched="$(printf '%s\n' "$files" | grep -E "$include" || true)"
if [ -n "$exclude" ] && [ -n "$matched" ]; then
	matched="$(printf '%s\n' "$matched" | grep -Ev "$exclude" || true)"
fi

if [ -n "$matched" ]; then
	say true "relevant: $(printf '%s\n' "$matched" | head -3 | paste -sd' ' -)"
else
	say false "none of $(printf '%s\n' "$files" | wc -l | tr -d ' ') changed files is relevant"
fi
