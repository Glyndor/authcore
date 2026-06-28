# Versioning & API stability

authcore ships the **latest** API on a single import path — only the newest
release is supported, and fixes (including security fixes) ship **forward** in a
new release, never back-ported. A version that is behind is upgraded, not patched
in place; the safe version is always the newest.

- **Move forward freely.** Improvements land on the `v1.x` line; any breaking
  change ships with clear migration notes in the release. The import path never
  changes — `go get` always resolves the newest, and Dependabot keeps you
  current.
- **No frozen API, no `/v2`.** The latest-only model is what keeps everyone on
  the fix; there is deliberately no parallel old-major path to linger on.

See the [Releases](https://github.com/Glyndor/authcore/releases) for the full
history and per-release migration notes.

Internal packages (`internal/…`) carry no compatibility guarantees at any
version and must not be imported from outside the module.
