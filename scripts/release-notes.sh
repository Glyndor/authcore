#!/usr/bin/env bash
# Usage: release-notes.sh <commit>
#
# Prints the curated notes for the release whose tag points at <commit>: the
# body of the merged pull request into main whose merge commit is <commit>,
# without its DCO trailer. release.yml passes the output to
# `gh release create --notes`, and --generate-notes appends the list of pull
# requests underneath.
#
# Exits non-zero, printing nothing on stdout, when no merged pull request into
# main has that merge commit, when its body is empty, or when it is labelled
# `breaking` and has no "## Breaking" section. v1.15.0 and v1.16.0 were
# published with generated notes only, so their breaking changes were stated
# nowhere on the release page until they were added by hand.
#
# Needs gh (authenticated, with GH_REPO or a checkout to pick the repository)
# and jq.
set -euo pipefail

commit="${1:?usage: release-notes.sh <commit>}"

# Only release pull requests target main, and gh lists newest first, so the
# one being released is near the top. A pull request that fell off the end of
# this page is reported as missing, which fails the release rather than
# publishing it without notes.
prs="$(gh pr list --state merged --base main --limit 50 --json number,mergeCommit,labels,body)"

pr="$(jq -c --arg commit "$commit" \
	'[.[] | select(.mergeCommit.oid == $commit)] | if length == 1 then .[0] else empty end' \
	<<<"$prs")"
if [ -z "$pr" ]; then
	echo "release-notes: no merged pull request into main has merge commit $commit" >&2
	exit 1
fi
number="$(jq -r '.number' <<<"$pr")"

# Drop carriage returns, then the trailing block of Signed-off-by lines and the
# blank lines around it. A Signed-off-by line inside the text stays.
body="$(jq -r '.body // ""' <<<"$pr" | tr -d '\r' | awk '
	{ line[NR] = $0 }
	END {
		n = NR
		while (n > 0 && (line[n] ~ /^[[:space:]]*$/ || line[n] ~ /^Signed-off-by: /)) n--
		for (i = 1; i <= n; i++) print line[i]
	}')"

if [ -z "$body" ]; then
	echo "release-notes: #$number has an empty body; write the release notes there" >&2
	exit 1
fi

if jq -e '[.labels[].name] | index("breaking")' <<<"$pr" >/dev/null; then
	if ! grep -q '^## Breaking' <<<"$body"; then
		echo "release-notes: #$number is labelled breaking and its body has no \"## Breaking\" section" >&2
		exit 1
	fi
fi

printf '%s\n' "$body"
