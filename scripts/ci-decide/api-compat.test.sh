#!/usr/bin/env bash
# Execute the API aggregate's real shell block for every decision/result pair.
# Also check the wiring that makes the required check evaluate failed decisions.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
workflow="$here/../../.github/workflows/api-compat.yml"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
passed=0
failed=0

awk '
	/^  api-compat-gate:$/ { block=1; next }
	block && /^  [^ ]/ { exit }
	block { print }
' "$workflow" >"$tmp/job.yml"
# These bindings are the boundary between Actions and the shell tested below.
# GitHub expressions must stay literal here; Bash must not expand them.
# shellcheck disable=SC2016
for binding in '    name: api compatibility' '    needs: [decide, api-compat]' \
	'    if: always()' '          DECIDE: ${{ needs.decide.result }}' \
	'          RUN: ${{ needs.decide.outputs.run }}' '          RESULT: ${{ needs.api-compat.result }}'; do
	if grep -qxF "$binding" "$tmp/job.yml"; then
		passed=$((passed + 1))
	else
		printf 'FAIL API gate wiring: missing %s\n' "$binding" >&2
		failed=$((failed + 1))
	fi
done
awk '
	/^        run: \|$/ { block=1; next }
	block && /^          / { sub(/^          /, ""); print; next }
	block { exit }
' "$tmp/job.yml" >"$tmp/gate.sh"
if [ ! -s "$tmp/gate.sh" ]; then
	printf 'FAIL API gate has no executable verdict\n' >&2
	exit 1
fi

# Only two triples may pass. Missing and malformed outputs cannot grant a skip.
for decision in success failure cancelled skipped ''; do
	for run in true false '' invalid; do
		for result in success failure cancelled skipped ''; do
			want=1
			if [ "$decision" = success ] && { [ "$run:$result" = true:success ] || [ "$run:$result" = false:skipped ]; }; then
				want=0
			fi
			got=0
			DECIDE="$decision" RUN="$run" RESULT="$result" bash "$tmp/gate.sh" >/dev/null 2>&1 || got=$?
			if [ "$got" -eq "$want" ]; then
				passed=$((passed + 1))
			else
				printf 'FAIL API gate decide=%q run=%q result=%q: exit=%s want=%s\n' \
					"$decision" "$run" "$result" "$got" "$want" >&2
				failed=$((failed + 1))
			fi
		done
	done
done
printf 'api-compat gate: passed %d, failed %d\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
