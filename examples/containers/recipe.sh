#!/usr/bin/env bash
# recipe.sh exercises the recommended setup from docs/containers.md end to
# end: keygen once, copy into a named volume, three read-only keep-id replicas
# with RequireExistingKeys, the guard against overwriting a populated volume,
# the recreate-survives-down -v check, and the empty-volume refusal.
#
# Invoked as `bash examples/containers/recipe.sh` from the repository root.
# It needs rootless Podman 5 or later, podup and Go on PATH.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

# Unique suffix for every resource this script creates, so two runs in
# parallel or a leftover from a previous run cannot collide.
suffix="$$-$(date +%s)"
project="authcore-recipe-${suffix}"
vol="authcore-recipe-keys-${suffix}"
empty_vol="authcore-recipe-empty-${suffix}"
image="localhost/authcore-probe:recipe"

uid="$(id -u)"
gid="$(id -g)"

tmp="$(mktemp -d -t authcore-recipe.XXXXXX)"

# Containers for this script carry the same podup project label, so a single
# `podman ps --filter label=...` is the reliable way to enumerate them. The
# label key matches what podup 5.10.x sets today (podup.project); if that
# ever changes, this filter is the only place that needs an update.
label="podup.project"

# Trap must never make the script exit non-zero on its own: a missing
# resource is fine, it just means an earlier step already cleaned it up. The
# script's real exit code is captured at trap entry and re-raised so a
# failed check still fails the script after the cleanup runs.
trap_rc=0
cleanup() {
    trap_rc=$?
    set +e
    # Containers go by label rather than through podup down, which would need
    # the compose variables of whichever step failed.
    for p in "$project" "${project}-empty"; do
        podman ps -aq --filter "label=${label}=${p}" | xargs -r podman rm -f >/dev/null 2>&1
    done
    podman volume rm "$vol" 2>/dev/null
    podman volume rm "$empty_vol" 2>/dev/null
    podman rmi -f "$image" 2>/dev/null
    rm -rf $tmp
    exit $trap_rc
}
trap cleanup EXIT

# wait_running polls until N containers of the given project are in state
# "running", or fails after the bounded deadline. Returns 0 on success, 1 on
# timeout. A failure prints the current state of every container it found.
wait_running() {
    local project_name="$1" want="$2" deadline_s="$3"
    local end=$((SECONDS + deadline_s))
    while [ "$SECONDS" -lt "$end" ]; do
        local running
        running="$(podman ps --filter "label=${label}=${project_name}" --filter status=running --format '{{.ID}}' | wc -l)"
        if [ "$running" -eq "$want" ]; then
            return 0
        fi
        sleep 2
    done
    echo "wait_running: timed out waiting for $want running container(s) of project $project_name" >&2
    echo "current container states:" >&2
    podman ps -a --filter "label=${label}=${project_name}" --format 'table {{.ID}} {{.Names}} {{.State}}' >&2
    return 1
}

# assert_logs_key_id asserts that exactly $want distinct containers of the
# project are running, that each printed the line "key id <id>", and that none
# logged a warning or an error. On failure it prints every container's
# state and logs before returning 1.
assert_logs_key_id() {
    local project_name="$1" want="$2" want_id="$3"
    local ids
    ids="$(podman ps --filter "label=${label}=${project_name}" --filter status=running --format '{{.ID}}' | sort)"
    local got
    got="$(printf '%s\n' "$ids" | grep -c . || true)"
    if [ "$got" -ne "$want" ]; then
        echo "assert_logs_key_id: expected $want running container(s) for $project_name, got $got" >&2
        echo "states:" >&2
        podman ps -a --filter "label=${label}=${project_name}" --format 'table {{.ID}} {{.Names}} {{.State}}' >&2
        for cid in $ids; do
            echo "--- logs $cid ---" >&2
            podman logs "$cid" >&2 || true
        done
        return 1
    fi
    local distinct
    distinct="$(printf '%s\n' "$ids" | sort -u | wc -l)"
    if [ "$distinct" -ne "$want" ]; then
        echo "assert_logs_key_id: expected $want distinct container ids, got $distinct" >&2
        return 1
    fi
    for cid in $ids; do
        local logs
        logs="$(podman logs "$cid" 2>&1 || true)"
        if ! printf '%s\n' "$logs" | grep -Fxq "key id $want_id"; then
            echo "assert_logs_key_id: container $cid did not log 'key id $want_id'" >&2
            echo "logs:" >&2
            printf '%s\n' "$logs" >&2
            return 1
        fi
        # docs/containers.md: on a read-only mount with RequireExistingKeys,
        # authcore performs no filesystem writes. A write it attempted there
        # would fail and be logged as a warning.
        if printf '%s\n' "$logs" | grep -Eq '^\[(WARN|ERROR)\]'; then
            echo "assert_logs_key_id: container $cid logged a warning or an error" >&2
            printf '%s\n' "$logs" >&2
            return 1
        fi
    done
    echo "ok: $want replicas of $project report key id $want_id, no warnings"
}

echo "== step 1: tools"
podman --version
podup --version
podman_major="$(podman --version | awk '{print $3}' | cut -d. -f1)"
if [ "$podman_major" -lt 5 ]; then
    echo "recipe: podman >= 5 required (rootless userns keep-id is the gate), got $podman_major" >&2
    exit 1
fi

echo "== step 2: build probe and image"
CGO_ENABLED=0 go -C examples/containers build -o "$tmp/probe" .
podman build -t "$image" -f examples/containers/Containerfile "$tmp"

echo "== step 3: keygen from checkout"
keygen_out="$(go run ./cmd/authcore-keygen -out "$tmp/keys")"
printf '%s\n' "$keygen_out"
key_id="$(printf '%s\n' "$keygen_out" | awk '/^key id /{print $3}')"
if [ -z "$key_id" ]; then
    echo "recipe: keygen did not print a 'key id' line" >&2
    exit 1
fi
echo "captured key id: $key_id"

echo "== step 4: copy keys into named volume"
podman volume create "$vol" \
    && podman run --rm --user "$uid:$gid" --userns=keep-id \
        -v "$tmp/keys:/src:ro" -v "$vol:/dst" \
        docker.io/library/debian:trixie-slim sh -c 'cp -p /src/* /dst/'

echo "== step 5: guard against overwriting a populated volume"
go run ./cmd/authcore-keygen -out "$tmp/keys2" >/dev/null
set +e
podman volume create "$vol" \
    && podman run --rm --user "$uid:$gid" --userns=keep-id \
        -v "$tmp/keys2:/src:ro" -v "$vol:/dst" \
        docker.io/library/debian:trixie-slim sh -c 'cp -p /src/* /dst/'
guard_rc=$?
set -e
if [ "$guard_rc" -eq 0 ]; then
    echo "recipe: guard failed: second copy into $vol succeeded (rc=0), expected non-zero" >&2
    exit 1
fi
echo "guard ok: second copy rejected with rc=$guard_rc"

echo "== step 6: three read-only replicas, all must report $key_id"
PROBE_UID="$uid" PROBE_GID="$gid" KEYS_VOLUME="$vol" \
    podup -p "$project" -f examples/containers/compose.yaml up -d
wait_running "$project" 3 60
assert_logs_key_id "$project" 3 "$key_id"

echo "== step 7: recreate via down -v preserves the external volume"
PROBE_UID="$uid" PROBE_GID="$gid" KEYS_VOLUME="$vol" \
    podup -p "$project" -f examples/containers/compose.yaml down -v
if ! podman volume exists "$vol"; then
    echo "recipe: external volume $vol was removed by 'down -v'; external: true should have kept it" >&2
    exit 1
fi
PROBE_UID="$uid" PROBE_GID="$gid" KEYS_VOLUME="$vol" \
    podup -p "$project" -f examples/containers/compose.yaml up -d
wait_running "$project" 3 60
assert_logs_key_id "$project" 3 "$key_id"

echo "== step 8: empty volume must refuse to start any replica"
podman volume create "$empty_vol"
empty_project="${project}-empty"
set +e
PROBE_UID="$uid" PROBE_GID="$gid" KEYS_VOLUME="$empty_vol" \
    podup -p "$empty_project" -f examples/containers/compose.yaml up -d
empty_up_rc=$?
set -e
echo "empty-volume up rc=$empty_up_rc (non-zero is acceptable and expected)"
# RequireExistingKeys makes the probe exit 1 immediately, so a container
# that did start produces a 'probe: ...' line and is then restarted by
# the unless-stopped policy. Poll every container of the project for
# the two invariants until the refusal is seen, and bail on the first
# 'key id' line we ever observe (the probe must not have produced one).
# A bounded wait caps the run; the cycle is short because the probe
# exits 1 and Podman restarts it within a second.
empty_seen_refusal=0
empty_end=$((SECONDS + 30))
empty_ids=""
while [ "$SECONDS" -lt "$empty_end" ]; do
    empty_ids="$(podman ps -a --filter "label=${label}=${empty_project}" --format '{{.ID}}')"
    if [ -z "$empty_ids" ]; then
        echo "assert: no containers were ever created for $empty_project" >&2
        podman ps -a --filter "label=${label}=${empty_project}" --format 'table {{.ID}} {{.Names}} {{.State}}' >&2
        exit 1
    fi
    empty_logs_concat=""
    for cid in $empty_ids; do
        logs="$(podman logs "$cid" 2>&1 || true)"
        empty_logs_concat="${empty_logs_concat}${logs}"$'\n'
        if printf '%s\n' "$logs" | grep -q '^key id '; then
            echo "recipe: empty-volume project produced a 'key id' line in $cid; the probe must refuse" >&2
            printf '%s\n' "$logs" >&2
            exit 1
        fi
    done
    if printf '%s\n' "$empty_logs_concat" | grep -q 'not complete in load-only mode'; then
        empty_seen_refusal=1
        break
    fi
    sleep 2
done
if [ "$empty_seen_refusal" -ne 1 ]; then
    echo "recipe: empty-volume refusal not observed in any container's logs within the bounded wait" >&2
    echo "container states:" >&2
    podman ps -a --filter "label=${label}=${empty_project}" --format 'table {{.ID}} {{.Names}} {{.State}}' >&2
    for cid in $empty_ids; do
        echo "--- logs $cid ---" >&2
        podman logs "$cid" 2>&1 >&2 || true
    done
    exit 1
fi
echo "ok: the empty volume was refused and no replica reported a key id"

echo "recipe: all checks passed"
