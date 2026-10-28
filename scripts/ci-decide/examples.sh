#!/usr/bin/env bash
# Emit one JSON array of affected example paths. Same environment as decide.sh.
# Keep its release policy: main, label changes and uncertain inputs run all.
# Cost measured 2026-10-27: #616 and #617 queued 7 unnecessary legs out of 10.
set -euo pipefail
examples=(modules/apikey modules/basic deploy/containers modules/email frameworks/fiber frameworks/gin modules/jwt modules/oauth modules/password modules/username)

emit() {
 local separator='' example
 printf '['
 for example in "$@"; do
  printf '%s"%s"' "$separator" "$example"
  separator=,
 done
 printf ']\n'
}
all() {
 emit "${examples[@]}"
 exit 0
}

[ "${EVENT:-}" = pull_request ] || all
[ "${BASE_REF:-}" = develop ] || all
case "${ACTION:-}" in
 labeled | unlabeled) all ;;
esac
if [ -z "${BASE:-}" ] || [ -z "${HEAD:-}" ]; then
 all
fi
files="$(mktemp)" || all
trap 'rm -f "$files"' EXIT
# NUL records preserve spaces, Unicode and newlines. Disable rename detection
# so both the source and destination of a move affect their respective legs.
if ! git diff --no-renames --name-only -z "${BASE}...${HEAD}" >"$files" 2>/dev/null; then
 all
fi
selected=()
while IFS= read -r -d '' file; do
 case "$file" in
  .github/workflows/examples.yml | scripts/ci-decide/* | examples/go.work) all ;;
 esac
 # Every shared Go input counts, including tests and nested module files.
 if [[ "$file" =~ ^([^/]+\.go|go\.(mod|sum))$ ||
       "$file" =~ ^(auth|internal)/(.*/)?([^/]+\.go|go\.(mod|sum))$ ]]; then
  all
 fi
 case "$file" in
  examples/*)
   known=false
   for example in "${examples[@]}"; do
    if [[ "$file" == "examples/$example/"* ]]; then
     selected+=("$example")
     known=true
     break
    fi
   done
   # A new example or workspace input is not evidence that nothing is affected.
   [ "$known" = true ] || all
   ;;
 esac
done <"$files"
# Stable order and no duplicates, independent of git's ordering of file names.
affected=()
for example in "${examples[@]}"; do
 for selected_example in "${selected[@]}"; do
  if [ "$example" = "$selected_example" ]; then
   affected+=("$example")
   break
  fi
 done
done
emit "${affected[@]}"
