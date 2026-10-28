#!/usr/bin/env bash
# Decides whether the jobs behind it have anything to look at.
#
#   decide.sh INCLUDE [EXCLUDE]
#
# INCLUDE and EXCLUDE are extended regular expressions over the paths a pull
# request changes. The answer is "run" when at least one changed path matches
# INCLUDE and does not match EXCLUDE. Pull requests into main always run every
# gate. It writes run=true or run=false to $GITHUB_OUTPUT (standard output
# when that is unset).
#
# It fails open: on any event other than a pull request, on a label change, and
# whenever it cannot read the diff, the answer is "run". A wrong "skip" would
# let a pull request merge without a gate having looked at it; a wrong "run"
# costs only minutes.
#
# Loading this script from the base does not make a pull_request workflow
# immutable: the PR can still edit its caller. Review workflow changes too.
#
# Environment: EVENT (github.event_name), ACTION (github.event.action), BASE and
# HEAD (the pull request's base and head commits), BASE_REF (its base branch).
# Cost reference, measured on 2026-10-27: full release gates took 29.4 min
# versus 15.5 min for a filtered release. The extra work validates the release.
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
if [ "${BASE_REF:-}" = "main" ]; then
	say true "release pull request into main always runs"
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
# NUL-separated and with quoting off: by default git prints a path with a
# character it does not like (a non-ASCII letter, a tab) inside double quotes
# with escapes, and that line would no longer match the include pattern, so a
# relevant file could make the whole check skip. A path that contains a newline
# is split in two by the conversion below, and each half is read as its own path;
# that can only turn a skip into a run, never the other way.
# Disable rename detection so both the removed origin and the added destination
# are tested, even when the destination has an irrelevant or excluded suffix.
if ! files="$(git -c core.quotePath=false diff --no-renames --name-only -z "${BASE}...${HEAD}" 2>/dev/null | tr '\0' '\n')"; then
	say true "could not read the diff"
	exit 0
fi
if [ -z "$files" ]; then
	if [ "${BASE_REF:-}" = "develop" ]; then
		say false "empty diff into develop"
	else
		say true "empty diff with unknown base branch"
	fi
	exit 0
fi

# Belt and braces: if any line still starts with a double quote the path was
# printed in git's quoted form and cannot be matched reliably, so run.
if printf '%s\n' "$files" | grep -q '^"'; then
	say true "a path came back quoted"
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
