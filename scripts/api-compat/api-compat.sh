#!/usr/bin/env bash
# api-compat.sh compares the public API of two checkouts of this module with
# apidiff and decides whether the change may merge.
#
#   api-compat.sh BASE_DIR HEAD_DIR
#
# The public API is every package that is not under internal/, tests/,
# examples/ or cmd/: the module root and auth/*. The two checkouts are compared
# package by package, because loading one package at a time keeps a compile
# error in an unrelated package (a test fixture, say) from hiding the answer.
#
# Verdict:
#   - no change, or only additions: exit 0. Additions are annotated as a
#     warning so a reviewer sees that the surface grew; they never fail.
#   - an incompatible change with the PR label `breaking`: exit 0, annotated.
#   - an incompatible change without it: exit 1.
#   - a removed package counts as incompatible; a new package as an addition.
#   - anything the script cannot decide (no apidiff, a package that does not
#     load): exit 2, never a pass.
#
# Environment:
#   APIDIFF     the apidiff binary (default: apidiff on PATH)
#   PR_LABELS   the pull request's labels, one per line; only an exact line
#               `breaking` acknowledges an incompatible change
#   GITHUB_ACTIONS, GITHUB_STEP_SUMMARY   set by Actions; when present the
#               verdict is also written as annotations and a job summary
set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: api-compat.sh BASE_DIR HEAD_DIR" >&2
	exit 2
fi
base_dir="$1"
head_dir="$2"
apidiff="${APIDIFF:-apidiff}"
labels="${PR_LABELS:-}"

if ! command -v "$apidiff" >/dev/null 2>&1; then
	echo "api-compat: apidiff not found ($apidiff)" >&2
	exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# public_packages prints the import paths of the public packages of a checkout.
public_packages() {
	local all
	# A failing go list must stop the script: an empty base list would make
	# every package of the head look new and the comparison would pass.
	if ! all="$(cd "$1" && go list ./...)"; then
		echo "api-compat: go list failed in $1" >&2
		exit 2
	fi
	printf '%s\n' "$all" | grep -Ev '/(internal|tests|examples|cmd)(/|$)' || true
}

module="$(cd "$head_dir" && go list -m)"
public_packages "$base_dir" | sort >"$work/base.pkgs"
public_packages "$head_dir" | sort >"$work/head.pkgs"
if [ ! -s "$head_dir/go.mod" ] || [ ! -s "$work/head.pkgs" ]; then
	echo "api-compat: no public package found in $head_dir" >&2
	exit 2
fi

# export_api writes the apidiff export data of package $2 in checkout $1.
export_api() {
	local dir="$1" pkg="$2" out="$3"
	if ! (cd "$dir" && "$apidiff" -w "$out" "$pkg") >"$work/export.log" 2>&1; then
		echo "api-compat: cannot load $pkg in $dir:" >&2
		cat "$work/export.log" >&2
		exit 2
	fi
}

incompatible=0
additions=0
report="$work/report.md"
: >"$report"

while read -r pkg; do
	short="${pkg#"$module"}"
	short="${short#/}"
	short="${short:-.}"
	in_base=0
	in_head=0
	grep -qxF "$pkg" "$work/base.pkgs" && in_base=1
	grep -qxF "$pkg" "$work/head.pkgs" && in_head=1

	if [ "$in_base" -eq 0 ]; then
		additions=$((additions + 1))
		printf '### %s\n\nnew package\n\n' "$short" >>"$report"
		continue
	fi
	if [ "$in_head" -eq 0 ]; then
		incompatible=$((incompatible + 1))
		printf '### %s\n\nIncompatible changes:\n- package removed\n\n' "$short" >>"$report"
		continue
	fi

	export_api "$base_dir" "$pkg" "$work/base.exp"
	export_api "$head_dir" "$pkg" "$work/head.exp"
	"$apidiff" "$work/base.exp" "$work/head.exp" >"$work/diff.txt"
	[ -s "$work/diff.txt" ] || continue

	if grep -q '^Incompatible changes:' "$work/diff.txt"; then
		incompatible=$((incompatible + $(awk '/^Incompatible changes:/{f=1;next} /^[A-Za-z].*:$/{f=0} f&&/^- /{n++} END{print n+0}' "$work/diff.txt")))
	fi
	if grep -q '^Compatible changes:' "$work/diff.txt"; then
		additions=$((additions + $(awk '/^Compatible changes:/{f=1;next} /^[A-Za-z].*:$/{f=0} f&&/^- /{n++} END{print n+0}' "$work/diff.txt")))
	fi
	{
		printf '### %s\n\n' "$short"
		cat "$work/diff.txt"
		printf '\n'
	} >>"$report"
done < <(sort -u "$work/base.pkgs" "$work/head.pkgs")

acknowledged=0
if printf '%s\n' "$labels" | grep -qxF 'breaking'; then
	acknowledged=1
fi

annotate() { # level title message
	if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
		printf '::%s title=%s::%s\n' "$1" "$2" "$3"
	fi
}

if [ "$incompatible" -eq 0 ] && [ "$additions" -eq 0 ]; then
	echo "api-compat: no change in the public API ($(wc -l <"$work/head.pkgs" | tr -d ' ') packages compared)"
	verdict="no change"
	status=0
else
	cat "$report"
	if [ "$incompatible" -gt 0 ]; then
		if [ "$acknowledged" -eq 1 ]; then
			annotate warning "Breaking API change" "$incompatible incompatible change(s), acknowledged by the breaking label"
			echo "api-compat: $incompatible incompatible change(s), acknowledged by the breaking label"
			verdict="incompatible, acknowledged"
			status=0
		else
			annotate error "Breaking API change" "$incompatible incompatible change(s) and the pull request has no breaking label"
			echo "api-compat: $incompatible incompatible change(s) and no breaking label; label the pull request or restore compatibility" >&2
			verdict="incompatible, NOT acknowledged"
			status=1
		fi
	else
		verdict="additions only"
		status=0
	fi
	if [ "$additions" -gt 0 ]; then
		annotate warning "Public API grew" "$additions addition(s) to the public API"
		echo "api-compat: $additions addition(s) to the public API"
	fi
fi
if [ "$acknowledged" -eq 1 ] && [ "$incompatible" -eq 0 ]; then
	annotate warning "Unneeded breaking label" "the pull request carries the breaking label but no incompatible change was found"
fi

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{
		printf '## Public API compatibility\n\nVerdict: **%s**\n\n' "$verdict"
		cat "$report"
	} >>"$GITHUB_STEP_SUMMARY"
fi
exit "$status"
