#!/usr/bin/env bash
# Real diffs exercise selection, trusted-base loading and the required gate.
# A selector that always returns all must fail the single-example/docs cases;
# a selector that drops shared inputs must fail the all-example cases.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
workflow="$here/../../.github/workflows/examples.yml"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
all='["modules/apikey","modules/basic","deploy/containers","modules/email","frameworks/fiber","frameworks/gin","modules/jwt","modules/oauth","modules/password","modules/username"]'
passed=0
failed=0
direct=true
awk '
 /      - id: decide/ { step=1 }
 step && /^        run: \|/ { block=1; next }
 block && /^          / { sub(/^          /, ""); print; next }
 block { exit }
' "$workflow" >"$tmp/loader.sh"
awk '
 /^          printf .*needs.decide.result=/ { block=1 }
 block { sub(/^          /, ""); print }
' "$workflow" >"$tmp/gate.sh"
git init -q "$tmp/r"
cd "$tmp/r"
git config user.email t@example.com
git config user.name t
git config commit.gpgsign false
mkdir -p examples/modules/jwt scripts/ci-decide docs
printf 'base\n' >examples/modules/jwt/main.go
printf 'base\n' >docs/guide.md
# Before the emitter exists, integration against the old workflow still runs.
if [ -f "$here/examples.sh" ]; then
 cp "$here/examples.sh" scripts/ci-decide/examples.sh
fi
git add -A
git commit -qm base
base="$(git rev-parse HEAD)"
change() {
 git checkout -q "$base"
 local file
 for file in "$@"; do
  mkdir -p "$(dirname "$file")"
  printf 'change\n' >>"$file"
 done
 git add -A
 git commit -qm change
 git rev-parse HEAD
}
check() {
 local name="$1" want="$2" head="$3" branch="${4-develop}" event="${5-pull_request}" action="${6-synchronize}" got run=true
 [ "$want" != '[]' ] || run=false
 if got="$(EVENT="$event" ACTION="$action" BASE="$base" HEAD="$head" BASE_REF="$branch" \
  RUNNER_TEMP="$tmp" GITHUB_OUTPUT=/dev/stdout bash "$tmp/loader.sh" 2>/dev/null)" && \
  [ "$got" = "$(printf 'examples=%s\nrun=%s' "$want" "$run")" ]; then
  passed=$((passed + 1))
 else
  printf 'FAIL %s: want examples=%s run=%s, got %q\n' "$name" "$want" "$run" "${got:-}" >&2
  failed=$((failed + 1))
 fi
 if [ "$direct" = true ]; then
  if got="$(EVENT="$event" ACTION="$action" BASE="$base" HEAD="$head" BASE_REF="$branch" \
   bash "$here/examples.sh" 2>/dev/null)" && [ "$got" = "$want" ]; then
   passed=$((passed + 1))
  else
   printf 'FAIL emitter %s: want %s, got %q\n' "$name" "$want" "${got:-}" >&2
   failed=$((failed + 1))
  fi
 fi
}
one="$(change examples/modules/jwt/main.go)"
docs="$(change docs/guide.md)"
check one-example '["modules/jwt"]' "$one"
check docs-only '[]' "$docs"
for example in modules/apikey modules/basic deploy/containers modules/email frameworks/fiber frameworks/gin modules/jwt modules/oauth modules/password modules/username; do
 check "$example" "[\"$example\"]" "$(change "examples/$example/main.go")"
done
check deduplicate '["modules/jwt"]' "$(change examples/modules/jwt/main.go examples/modules/jwt/README.md)"
check workspace-sum "$all" "$(change examples/go.work.sum)"
check shared-unusual "$all" "$(change $'auth/jwt/ñ with\nnewline.go')"
for file in authcore.go go.mod go.sum auth/jwt/jwt.go \
 internal/nested/value.go auth/nested/go.mod internal/nested/go.sum examples/go.work \
 .github/workflows/examples.yml scripts/ci-decide/examples.sh; do
 check "$file" "$all" "$(change "$file")"
done
# Workspace dependency directives can affect every member, even when the
# changed member does not import the dependency whose resolution it changes.
for example in modules/apikey modules/basic deploy/containers modules/email frameworks/fiber frameworks/gin modules/jwt modules/oauth modules/password modules/username; do
 for dependency in go.mod go.sum; do
  check "workspace:$example/$dependency" "$all" "$(change "examples/$example/$dependency")"
 done
 check "example-test:$example" "[\"$example\"]" "$(change "examples/$example/main_test.go")"
done
check nested-module "$all" "$(change examples/modules/username/review-jwt/go.mod)"
# Dependency tests are not compiled or executed by consumers. Their production
# siblings and the tests belonging to an example remain covered above.
for file in root_test.go auth/jwt/jwt_test.go internal/nested/value_test.go; do
 check "dependency-test:$file" '[]' "$(change "$file")"
 check "main-dependency-test:$file" "$all" "$(change "$file")" main
done
check mixed-library-test '["modules/jwt"]' "$(change auth/jwt/jwt_test.go examples/modules/jwt/main.go)"
check mixed-library-source "$all" "$(change auth/jwt/jwt.go examples/modules/jwt/main.go)"
check two-examples '["frameworks/gin","modules/jwt"]' "$(change examples/frameworks/gin/main.go examples/modules/jwt/main.go)"
check example-doc '["modules/jwt"]' "$(change examples/modules/jwt/README.md)"
check unusual-name '["modules/jwt"]' "$(change $'examples/modules/jwt/ñ with\nnewline.go')"
check unknown-example "$all" "$(change examples/modules/new/main.go)"
check unrelated-go '[]' "$(change tests/meta/policy_test.go cmd/tool/main.go)"
check empty-develop '[]' "$base"
check main-docs "$all" "$docs" main
check main-empty "$all" "$base" main
check unreadable-diff "$all" deadbeef
check missing-head "$all" ''
check unknown-base "$all" "$docs" ''
check push "$all" "$docs" develop push
check label "$all" "$docs" develop pull_request labeled
check unlabel "$all" "$docs" develop pull_request unlabeled
# Renames must cover the old and new folders, including moves out of examples.
git checkout -q "$base"
mkdir -p examples/modules/basic
git mv examples/modules/jwt/main.go examples/modules/basic/main.go
git commit -qm rename
check rename '["modules/basic","modules/jwt"]' "$(git rev-parse HEAD)"
git checkout -q "$base"
git mv examples/modules/jwt/main.go docs/moved.go
git commit -qm move-out
check move-out '["modules/jwt"]' "$(git rev-parse HEAD)"
# Install broken/old trusted emitters. Candidate checkout must never be used.
# The checkout can contain hostile candidate code; the loader reads only base.
printf 'touch "%s/candidate-ran"\nprintf '\''[]\\n'\''\n' "$tmp" >scripts/ci-decide/examples.sh
direct=false
check trusted-base '[]' "$docs"
direct=true
if [ -e "$tmp/candidate-ran" ]; then
 printf 'FAIL candidate selector executed\n' >&2
 exit 1
fi
git checkout -q -- scripts/ci-decide/examples.sh
original_base="$base"
direct=false
while IFS= read -r body; do
 git checkout -q "$original_base"
 mkdir -p scripts/ci-decide
 if [ "$body" = missing ]; then
  rm -f scripts/ci-decide/examples.sh
 else
  printf '#!/usr/bin/env bash\n%s\n' "$body" >scripts/ci-decide/examples.sh
 fi
 git add -A
 git commit -qm broken --allow-empty
 base="$(git rev-parse HEAD)"
 if [ "$body" = "printf '[]\n'" ]; then
  check stale-selector-main "$all" "$base" main
 else
  check "bad-selector:$body" "$all" "$base"
 fi
done <<'CASES'
exit 1
printf 'garbage\n'
printf '["unknown"]\n'
printf '["modules/jwt","modules/jwt"]\n'
printf '[]\n[]\n'
printf '{"example":[]}\n'
printf 'null\n'
printf '[1]\n'
printf '[]\n'; exit 1
missing
printf '[]\n'
CASES
# Required check: only an intentional skip or a successful matrix may pass.
for decision in success failure cancelled skipped; do
 for run in true false ''; do
  for result in success failure cancelled skipped; do
   want=1
   if [ "$decision" = success ] && { [ "$run:$result" = true:success ] || [ "$run:$result" = false:skipped ]; }; then
    want=0
   fi
   got=0
   DECIDE="$decision" RUN="$run" RESULT="$result" bash "$tmp/gate.sh" >/dev/null 2>&1 || got=$?
   if [ "$got" -eq "$want" ]; then
    passed=$((passed + 1))
   else
    printf 'FAIL gate %s:%s:%s exit=%s want=%s\n' "$decision" "$run" "$result" "$got" "$want" >&2
    failed=$((failed + 1))
   fi
  done
 done
done
printf 'examples: passed %d, failed %d\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
