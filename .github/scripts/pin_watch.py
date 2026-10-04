#!/usr/bin/env python3
r"""Watch tool versions pinned by hand in CI workflows.

Four tool versions in CI are pinned by hand: golangci-lint, podup,
actionlint, shellcheck. Dependabot does not see the strings in an
`env:` block, so a new upstream release can land without anyone
noticing, the way podup 5.10.11 did on 2026-10-04. The response is
this script: every run, for each pin, ask `gh release view` what the
upstream latest non-prerelease tag is and compare against the value
in the workflow. A mismatch opens (or refreshes) one drift issue.

The four pins live in this file as data, one row per tool. Adding a
hand-pinned tool means adding a row here and nothing else; the report
and the issue body are derived from it.

Usage:
  python3 .github/scripts/pin_watch.py --report
  python3 .github/scripts/pin_watch.py --issue

`--report` (default) prints one line per pin and exits 0 even on
drift. `--issue` does the same, and if any pin has drifted, keeps
exactly one open issue titled `ci: pinned tool versions have drifted`:
existing issue is edited, missing one is created. A watcher that
cannot read a pin or cannot reach upstream exits 1 in either mode;
that is the only way `--report` exits non-zero, and the same condition
in `--issue` short-circuits before the issue call so a half-formed
issue is never written.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

# Each row: human name, workflow path (relative to the repo root),
# env var carrying the version, upstream GitHub repo. Adding a hand
# pin is a row here and a bump in the workflow; the report, the test
# that reads the real files, and the issue body all derive from it.
PINS = (
	("golangci-lint", ".github/workflows/ci.yml",          "GOLANGCI_LINT_VERSION", "golangci/golangci-lint"),
	("podup",         ".github/workflows/containers.yml",  "PODUP_VERSION",         "Glyndor/podup"),
	("actionlint",    ".github/workflows/workflow-lint.yml", "ACTIONLINT_VERSION",  "rhysd/actionlint"),
	("shellcheck",    ".github/workflows/workflow-lint.yml", "SHELLCHECK_VERSION",  "koalaman/shellcheck"),
)

ISSUE_TITLE = "ci: pinned tool versions have drifted"
ISSUE_LABELS = ("type:ci", "prio:P3", "effort:XS", "status:triage")

# Read the repo root from the script's own location so a checkout
# inside an actions runner and a local run from anywhere resolve the
# same paths.
REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def read_pin(text: str, var: str) -> str:
	r"""Return the value of `VAR:` in a workflow file's text.

	Matches `^\s*VAR:\s*"?([^"\s#]+)` on its own line, accepting both
	the quoted and the unquoted form and ignoring a trailing `#`
	comment. A variable that does not appear, or that appears with two
	different values, raises `ValueError`; two equal values are
	returned as the single value. The strict equality on duplicates is
	deliberate: a pin that drifts inside a single file is the bug, not
	a feature to normalise away.
	"""
	pattern = re.compile(r'^\s*' + re.escape(var) + r':\s*"?([^"\s#]+)', flags=re.MULTILINE)
	matches = [m.group(1) for m in pattern.finditer(text)]
	if not matches:
		raise ValueError(f"variable {var!r} not found in workflow text")
	first = matches[0]
	for other in matches[1:]:
		if other != first:
			raise ValueError(
				f"variable {var!r} appears with two different values: {first!r} vs {other!r}"
			)
	return first


def normalize(version: str) -> str:
	"""Strip one leading `v` so `v1.7.12` compares equal to `1.7.12`.

	Comparison is by string equality only; semver ordering is
	intentionally not done because a pin that lags upstream is the
	same kind of drift as a pin that has overshot, and the script's
	job is to surface both as a single verdict.
	"""
	if version.startswith("v"):
		return version[1:]
	return version


def latest(repo: str) -> str:
	"""Return the latest non-prerelease tag of `repo`.

	Runs `gh release view --repo <repo> --json tagName --jq .tagName`
	via `subprocess.run(..., check=True)`. Raises `RuntimeError` on
	a failed call or empty output.
	"""
	cmd = ["gh", "release", "view", "--repo", repo, "--json", "tagName", "--jq", ".tagName"]
	try:
		proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
	except subprocess.CalledProcessError as exc:
		raise RuntimeError(
			f"gh release view failed for {repo} (exit {exc.returncode}): "
			f"{exc.stderr.strip() or exc.stdout.strip()}"
		) from exc
	except FileNotFoundError as exc:
		raise RuntimeError("gh not found on PATH; install the GitHub CLI to query upstream") from exc
	tag = proc.stdout.strip()
	if not tag:
		raise RuntimeError(f"gh release view returned an empty tag for {repo}")
	return tag


def gather(pins, repo_root: Path, read_text, latest_for) -> list:
	"""Read every pin and ask upstream. Returns rows in pin order.

	Each row is `(name, file, var, repo, pinned, upstream)`. Any
	exception from `read_pin` or `latest_for` propagates so the caller
	can decide between exit 1 and the silent path.
	"""
	rows = []
	for name, rel, var, repo in pins:
		rows.append((name, rel, var, repo, read_pin(read_text(Path(repo_root) / rel), var), latest_for(repo)))
	return rows


def report(rows, out) -> list:
	"""Print one line per pin; return the drift subset.

	Order matches `PINS` so a diff of two runs is itself a report.
	"""
	drift = []
	for name, rel, _var, _repo, pinned, upstream in rows:
		drifted = normalize(pinned) != normalize(upstream)
		print(f"{name} pinned={pinned} latest={upstream} {'DRIFT' if drifted else 'ok'}", file=out)
		if drifted:
			drift.append((name, rel, pinned, upstream))
	return drift


def render_issue_body(drift: list) -> str:
	"""Render the markdown body for the drift issue.

	A short table of the drifted pins, one row per pin, followed by
	the one-line procedure.
	"""
	lines = [
		"Pinned tool versions in CI workflows have drifted from their upstream releases:",
		"",
		"| name | file | pinned | latest |",
		"| --- | --- | --- | --- |",
	]
	for name, rel, pinned, upstream in drift:
		lines.append(f"| {name} | `{rel}` | `{pinned}` | `{upstream}` |")
	lines.append("")
	lines.append(
		"Bump the version and its sha256 together from the upstream release, and read the release notes first."
	)
	return "\n".join(lines) + "\n"


def reconcile_issue(
	drift: list,
	*,
	find_open_issues,
	edit_issue,
	create_issue,
	render_body=render_issue_body,
	title: str = ISSUE_TITLE,
	labels=ISSUE_LABELS,
	out,
) -> int:
	"""Open or refresh the single drift issue.

	The three gh-callable functions are injected so the tests can
	exercise every branch without `gh` on the path.
	"""
	if not drift:
		return 0
	target = next(
		(issue for issue in (find_open_issues() or []) if isinstance(issue, dict) and issue.get("title") == title),
		None,
	)
	body = render_body(drift)
	if target is not None:
		edit_issue(target["number"], body)
		print(f"pin watch: updated issue #{target['number']}", file=out)
	else:
		create_issue(title, body, labels)
		print("pin watch: opened drift issue", file=out)
	return 0


# The gh-callable wrappers. Each is thin: parse or render, then a
# single subprocess call, and they raise `RuntimeError` on non-zero
# exit so `reconcile_issue` does not have to know about
# `subprocess.CalledProcessError`.


def find_open_issues() -> list:
	"""List open issues whose title contains the drift title.

	The search is a substring over the title; the Python side keeps
	only the exact match. The substring is what keeps the listing
	cheap, and the exact match is what prevents a renamed or
	superseding issue from being edited as the canonical one.
	"""
	cmd = [
		"gh", "issue", "list",
		"--state", "open",
		"--search", f'in:title "{ISSUE_TITLE}"',
		"--json", "number,title",
	]
	try:
		proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
	except subprocess.CalledProcessError as exc:
		raise RuntimeError(f"gh issue list failed (exit {exc.returncode}): {exc.stderr.strip()}") from exc
	try:
		parsed = json.loads(proc.stdout)
	except json.JSONDecodeError as exc:
		raise RuntimeError(f"gh issue list returned non-JSON: {proc.stdout!r}") from exc
	if not isinstance(parsed, list):
		raise RuntimeError("gh issue list did not return a JSON list")
	return parsed


def edit_issue(number: int, body: str) -> None:
	"""Replace the body of an existing issue."""
	cmd = ["gh", "issue", "edit", str(number), "--body-file", "-"]
	try:
		subprocess.run(cmd, input=body, capture_output=True, text=True, check=True)
	except subprocess.CalledProcessError as exc:
		raise RuntimeError(f"gh issue edit failed for #{number} (exit {exc.returncode}): {exc.stderr.strip()}") from exc


def create_issue(title: str, body: str, labels) -> None:
	"""Open a new issue with the drift title, body and labels."""
	cmd = ["gh", "issue", "create", "--title", title, "--body-file", "-"]
	for label in labels:
		cmd.extend(["--label", label])
	try:
		subprocess.run(cmd, input=body, capture_output=True, text=True, check=True)
	except subprocess.CalledProcessError as exc:
		raise RuntimeError(f"gh issue create failed (exit {exc.returncode}): {exc.stderr.strip()}") from exc


def _parse_args(argv: list) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Report (and optionally reconcile) drift in hand-pinned CI tool versions.",
	)
	mode = parser.add_mutually_exclusive_group()
	mode.add_argument("--report", action="store_true", help="Print the per-pin report and exit (default).")
	mode.add_argument("--issue", action="store_true", help="Open or refresh the single drift issue if any pin has drifted.")
	return parser.parse_args(argv)


def main(argv: list) -> int:
	args = _parse_args(argv)
	try:
		rows = gather(PINS, REPO_ROOT, Path.read_text, latest)
	except (ValueError, RuntimeError) as exc:
		print(f"could not read pins or query upstream: {exc}", file=sys.stderr)
		return 1
	drift = report(rows, sys.stdout)
	# Only --issue writes. Reporting is the default, so the branch keys on
	# the flag that asks for the write rather than on the one that does not.
	if not args.issue:
		return 0
	try:
		return reconcile_issue(
			drift,
			find_open_issues=find_open_issues,
			edit_issue=edit_issue,
			create_issue=create_issue,
			out=sys.stdout,
		)
	except (RuntimeError, subprocess.CalledProcessError) as exc:
		print(f"could not reconcile the drift issue: {exc}", file=sys.stderr)
		return 1


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
