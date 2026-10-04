#!/usr/bin/env python3
"""Tests for `.github/scripts/pin_watch.py`.

Run from the repository root with:

	python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v

Each test fails for a specific reason if the script is wrong:

- `TestReadPin` pins down the regex one behaviour at a time: quoted,
  unquoted, indented, trailing comment, missing variable, two equal
  values, two different values.
- `TestNormalize` covers the leading-`v` rule, which is the only
  place a `v`-prefixed pin and an unprefixed one can compare equal.
- `TestReport` drives `gather` and `report` with a fake `latest_for`
  so the verdict is checked, not the upstream call.
- `TestReconcile` exercises the four `reconcile_issue` branches with
  injected fakes, so no `gh` call is ever made under test.
- `TestRealWorkflows` reads the four workflow files in the worktree
  and asserts every pin in the table parses. Renaming an env var
  without updating the table turns the suite red.
"""

import io
import sys
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / ".github" / "scripts"))

import pin_watch as pw  # noqa: E402


class TestReadPin(unittest.TestCase):
	"""The regex one shape at a time."""

	def test_unquoted_value(self) -> None:
		self.assertEqual(pw.read_pin("FOO: 1.2.3\n", "FOO"), "1.2.3")

	def test_quoted_value(self) -> None:
		self.assertEqual(pw.read_pin('FOO: "1.2.3"\n', "FOO"), "1.2.3")

	def test_indented_value(self) -> None:
		# Workflow `env:` blocks are indented under the job; the regex
		# must accept the leading whitespace the way YAML emits it.
		self.assertEqual(pw.read_pin("      GOLANGCI_LINT_VERSION: 2.14.0\n", "GOLANGCI_LINT_VERSION"), "2.14.0")

	def test_trailing_comment_ignored(self) -> None:
		self.assertEqual(pw.read_pin("FOO: 1.2.3 # the version\n", "FOO"), "1.2.3")

	def test_missing_variable_raises(self) -> None:
		with self.assertRaises(ValueError):
			pw.read_pin("BAR: 1.2.3\n", "FOO")

	def test_two_different_values_raise(self) -> None:
		with self.assertRaises(ValueError):
			pw.read_pin("FOO: 1.2.3\nFOO: 1.2.4\n", "FOO")

	def test_two_equal_values_accepted(self) -> None:
		self.assertEqual(pw.read_pin("FOO: 1.2.3\nFOO: 1.2.3\n", "FOO"), "1.2.3")


class TestNormalize(unittest.TestCase):
	"""The leading-`v` rule, both halves."""

	def test_stripped_v_prefix_equals_bare(self) -> None:
		self.assertEqual(pw.normalize("v1.7.12"), pw.normalize("1.7.12"))

	def test_strips_only_one_v(self) -> None:
		# A double-`v` is not a shape the four pins use, but the rule
		# says "one leading `v`", and the test pins that down.
		self.assertEqual(pw.normalize("vv1.0.0"), "v1.0.0")


class TestReport(unittest.TestCase):
	"""Driven with a fake `latest_for`; upstream is never touched."""

	def _gather(self, pins, latest_map: dict, text_map: dict) -> list:
		def read_text(path: Path) -> str:
			return text_map[str(Path(path).name)]

		def latest_for(repo: str) -> str:
			return latest_map[repo]

		return pw.gather(pins, Path("/tmp"), read_text, latest_for)

	def test_all_equal_no_drift(self) -> None:
		pins = (("a", "p.yml", "A", "r1"),)
		rows = self._gather(pins, {"r1": "1.0.0"}, {"p.yml": "A: 1.0.0\n"})
		drift = pw.report(rows, io.StringIO())
		self.assertEqual(drift, [])

	def test_one_different_reports_that_pin_with_both_values(self) -> None:
		pins = (
			("a", "p.yml", "A", "r1"),
			("b", "q.yml", "B", "r2"),
		)
		rows = self._gather(
			pins,
			{"r1": "1.0.0", "r2": "2.0.1"},
			{"p.yml": "A: 1.0.0\n", "q.yml": "B: 2.0.0\n"},
		)
		drift = pw.report(rows, io.StringIO())
		self.assertEqual(len(drift), 1)
		name, _rel, pinned, upstream = drift[0]
		self.assertEqual(name, "b")
		self.assertEqual(pinned, "2.0.0")
		self.assertEqual(upstream, "2.0.1")

	def test_v_prefix_only_difference_does_not_drift(self) -> None:
		# `v1.0.0` and `1.0.0` must compare equal; the verifier cannot
		# tell a tool's history from its tag, and pretending otherwise
		# would be a false positive on the very first run.
		pins = (("a", "p.yml", "A", "r1"),)
		rows = self._gather(pins, {"r1": "v1.0.0"}, {"p.yml": "A: 1.0.0\n"})
		drift = pw.report(rows, io.StringIO())
		self.assertEqual(drift, [])


class TestReconcile(unittest.TestCase):
	"""`reconcile_issue` driven with three injected fakes."""

	def _run(self, drift, issues: list):
		created = []
		edited = []

		def find_open_issues():
			return issues

		def create_issue(title, body, labels):
			created.append({"title": title, "body": body, "labels": labels})

		def edit_issue(number, body):
			edited.append({"number": number, "body": body})

		rc = pw.reconcile_issue(
			drift,
			find_open_issues=find_open_issues,
			edit_issue=edit_issue,
			create_issue=create_issue,
			out=io.StringIO(),
		)
		return rc, created, edited

	def test_drift_no_open_issue_creates_with_exact_title_and_body(self) -> None:
		drift = [("actionlint", ".github/workflows/workflow-lint.yml", "v1.7.12", "v1.7.13")]
		rc, created, edited = self._run(drift, [])
		self.assertEqual(rc, 0)
		self.assertEqual(edited, [])
		self.assertEqual(len(created), 1)
		self.assertEqual(created[0]["title"], pw.ISSUE_TITLE)
		self.assertEqual(tuple(created[0]["labels"]), pw.ISSUE_LABELS)
		self.assertIn("actionlint", created[0]["body"])
		self.assertIn("v1.7.12", created[0]["body"])
		self.assertIn("v1.7.13", created[0]["body"])

	def test_drift_open_issue_with_exact_title_is_edited(self) -> None:
		drift = [("actionlint", ".github/workflows/workflow-lint.yml", "v1.7.12", "v1.7.13")]
		rc, created, edited = self._run(drift, [{"number": 42, "title": pw.ISSUE_TITLE}])
		self.assertEqual(rc, 0)
		self.assertEqual(created, [])
		self.assertEqual(len(edited), 1)
		self.assertEqual(edited[0]["number"], 42)
		self.assertIn("v1.7.13", edited[0]["body"])

	def test_drift_open_issue_with_only_substring_match_treated_as_no_match(self) -> None:
		# The exact-match check must be exact: a superseding or
		# follow-up issue that happens to contain the title in its own
		# must not be edited as if it were the canonical one.
		drift = [("actionlint", ".github/workflows/workflow-lint.yml", "v1.7.12", "v1.7.13")]
		rc, created, edited = self._run(drift, [{"number": 99, "title": f"re: {pw.ISSUE_TITLE} follow-up"}])
		self.assertEqual(rc, 0)
		self.assertEqual(edited, [])
		self.assertEqual(len(created), 1)
		self.assertEqual(created[0]["title"], pw.ISSUE_TITLE)

	def test_no_drift_neither_create_nor_edit_called(self) -> None:
		rc, created, edited = self._run([], [{"number": 42, "title": pw.ISSUE_TITLE}])
		self.assertEqual(rc, 0)
		self.assertEqual(created, [])
		self.assertEqual(edited, [])


class TestRenderBody(unittest.TestCase):
	"""The body of the drift issue."""

	def test_renders_drift_table_and_procedure_sentence(self) -> None:
		body = pw.render_issue_body([
			("actionlint", ".github/workflows/workflow-lint.yml", "v1.7.12", "v1.7.13"),
			("shellcheck", ".github/workflows/workflow-lint.yml", "v0.11.0", "v0.11.1"),
		])
		self.assertIn("actionlint", body)
		self.assertIn("shellcheck", body)
		self.assertIn("v1.7.12", body)
		self.assertIn("v1.7.13", body)
		self.assertIn("sha256", body)
		self.assertIn("release notes", body)
		self.assertIn("| name | file | pinned | latest |", body)


class TestMain(unittest.TestCase):
	"""Which mode writes. Only --issue may reach the issue calls."""

	ROWS = [("podup", ".github/workflows/containers.yml", "PODUP_VERSION", "Glyndor/podup", "5.10.10", "v5.10.11")]

	def run_main(self, argv):
		create = mock.Mock()
		with mock.patch.object(pw, "gather", return_value=self.ROWS), \
				mock.patch.object(pw, "find_open_issues", return_value=[]), \
				mock.patch.object(pw, "edit_issue"), \
				mock.patch.object(pw, "create_issue", create), \
				mock.patch("sys.stdout", new_callable=io.StringIO):
			rc = pw.main(argv)
		return rc, create

	def test_issue_mode_opens_the_issue_on_drift(self):
		rc, create = self.run_main(["--issue"])
		self.assertEqual(rc, 0)
		create.assert_called_once()
		self.assertEqual(create.call_args.args[0], pw.ISSUE_TITLE)

	def test_report_mode_never_writes(self):
		for argv in ([], ["--report"]):
			with self.subTest(argv=argv):
				rc, create = self.run_main(argv)
				self.assertEqual(rc, 0)
				create.assert_not_called()


class TestRealWorkflows(unittest.TestCase):
	"""Every pin in the table must parse from the real workflow file.

	Renaming an env var without updating `PINS` (or vice versa) is a
	merge that should not be possible; this test is the gate.
	"""

	def test_every_pin_in_table_parses(self) -> None:
		for name, rel, var, _repo in pw.PINS:
			with self.subTest(pin=name):
				text = (REPO_ROOT / rel).read_text(encoding="utf-8")
				value = pw.read_pin(text, var)
				self.assertTrue(value, f"{name}: empty value for {var} in {rel}")


if __name__ == "__main__":
	unittest.main()
