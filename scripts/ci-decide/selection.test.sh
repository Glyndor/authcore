#!/usr/bin/env bash
# Read the real workflow filters and exercise their boundaries with real diffs.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
workflows="$here/../../.github/workflows"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
passed=0
failed=0
git init -q "$tmp/r"
cd "$tmp/r"
git config user.email t@example.com
git config user.name t
git config commit.gpgsign false
printf 'base\n' >base.txt
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
 local workflow="$1" want="$2" head="$3" branch="${4-develop}" got
 local include exclude
 include="$(awk -F "'" '$1 == "          INCLUDE: " { print $2 }' "$workflows/$workflow.yml")"
 exclude="$(awk -F "'" '$1 == "          EXCLUDE: " { print $2 }' "$workflows/$workflow.yml")"
 if got="$(EVENT=pull_request ACTION=synchronize BASE="$base" HEAD="$head" BASE_REF="$branch" \
  GITHUB_OUTPUT=/dev/stdout bash "$here/decide.sh" "$include" "$exclude" 2>/dev/null)" && [ "$got" = "run=$want" ]; then
  passed=$((passed + 1))
 else
  printf 'FAIL %s (%s): want run=%s, got %q; paths: %s\n' \
   "$workflow" "$branch" "$want" "${got:-}" "$(git diff --name-only "$base...$head" | paste -sd, -)" >&2
  failed=$((failed + 1))
 fi
}

# Root lint, audit and portability never enter the nested example modules.
for file in examples/modules/username/main.go examples/modules/username/main_test.go \
 examples/frameworks/gin/main.go examples/deploy/containers/main.go; do
 head="$(change "$file")"
 for workflow in ci audit portability; do
  check "$workflow" false "$head"
  check "$workflow" true "$head" main
 done
done
for workflow in ci audit portability containers; do
 for file in authcore.go auth/jwt/jwt.go internal/clock/clock.go cmd/tool/main.go go.mod go.sum \
  ".github/workflows/$workflow.yml"; do
  check "$workflow" true "$(change "$file")"
 done
 check "$workflow" true "$(change examples/modules/username/main.go auth/jwt/jwt.go)"
 check "$workflow" false "$(change docs/guide.md)"
done
for workflow in ci portability; do
 for file in auth/jwt/jwt_test.go internal/clock/clock_test.go tests/meta/policy_test.go; do
  check "$workflow" true "$(change "$file")"
 done
done
check ci true "$(change .golangci.yml)"

# The recipe builds in the workspace: another member's dependencies can change
# its build, even though that member's own Go sources cannot.
for file in examples/modules/username/main.go examples/modules/username/main_test.go \
 examples/frameworks/gin/main.go examples/frameworks/fiber/main_test.go; do
 head="$(change "$file")"
 check containers false "$head"
 check containers true "$head" main
done
for file in examples/deploy/containers/main.go examples/deploy/containers/main_test.go \
 examples/deploy/containers/recipe.sh examples/deploy/containers/compose.yaml \
 examples/deploy/containers/Containerfile examples/go.work examples/go.work.sum \
 examples/modules/username/go.mod examples/modules/username/go.sum \
 examples/frameworks/gin/go.mod examples/deploy/containers/go.sum docs/guides/containers.md; do
 check containers true "$(change "$file")"
done
# Unclassified inputs stay eligible until their dependency scope is known.
check containers true "$(change examples/new/main.go)"

# Meta tests inspect the tree; the hostile suite neither runs nor imports them.
# Preserve production helpers and every input inside the hostile suite.
for file in tests/meta/docs_scope_test.go tests/meta/nested/policy_test.go; do
 head="$(change "$file")"
 check hostile false "$head"
 check hostile true "$head" main
 check ci true "$head"
 check portability true "$head"
done
for file in tests/hostile/attack_test.go tests/hostile/meta/policy_test.go \
 tests/hostile/support.go tests/hostile/testdata/input.json tests/meta/shared.go \
 tests/shared/support.go tests/other/policy_test.go auth/jwt/jwt.go internal/clock/clock.go \
 cmd/tool/main.go go.mod go.sum .github/workflows/hostile.yml; do
 check hostile true "$(change "$file")"
done
check hostile true "$(change tests/meta/docs_scope_test.go tests/hostile/attack_test.go)"
check hostile true "$(change tests/meta/docs_scope_test.go auth/jwt/jwt.go)"
printf 'selection: passed %d, failed %d\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
