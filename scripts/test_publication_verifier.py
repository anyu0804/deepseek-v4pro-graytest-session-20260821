#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synthetic regression tests for repository publication privacy verification.

CRITICAL PRIVACY REQUIREMENT:
The real private username or real private identifiers must NEVER appear in any
test fixture or test output. All test fixtures use completely synthetic tokens.

Tests cover:
  1. Detection of fake private username represented only as split \\uXXXX escapes
     in Markdown (causing publication gate to FAIL).
  2. Synthetic placeholder replacement causing publication gate to PASS.
  3. Detection of raw seeded private literal in text.
  4. Detection of percent-encoded and HTML-entity forms.
  5. Privacy assurance: test/log/report output NEVER reveals the tested private literal.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

# Import the verifier components
try:
    from scripts.verify_publication import (
        ALLOWED_PUBLICATION_EMAIL,
        ALLOWED_PUBLICATION_NAME,
        collect_target_literals,
        decode_split_html_entities,
        decode_split_percent_escapes,
        decode_split_unicode_escapes,
        decode_unicode_escapes,
        get_decoded_representations,
        scan_content,
        verify_commit_metadata,
        verify_publication,
    )
except ImportError:
    from verify_publication import (
        ALLOWED_PUBLICATION_EMAIL,
        ALLOWED_PUBLICATION_NAME,
        collect_target_literals,
        decode_split_html_entities,
        decode_split_percent_escapes,
        decode_split_unicode_escapes,
        decode_unicode_escapes,
        get_decoded_representations,
        scan_content,
        verify_commit_metadata,
        verify_publication,
    )

# Completely synthetic test literals - NEVER real identifiers
SYNTHETIC_TARGET_USER = "假名测试"
SYNTHETIC_TARGET_PROJECT = "synth_project_mod_42"


def _rmtree_force(path):
    """Delete a temp tree even when git has left read-only object files (Windows)."""
    if not os.path.exists(path):
        return
    import stat
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                os.chmod(os.path.join(root, name), stat.S_IWRITE)
            except OSError:
                pass
    shutil.rmtree(path)


class TestPublicationVerifier(unittest.TestCase):
    """Regression test suite for publication privacy verification gate."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_pub_verify_")
        self.targets = {
            "winuser": {SYNTHETIC_TARGET_USER},
            "project": {SYNTHETIC_TARGET_PROJECT},
        }

    def tearDown(self):
        _rmtree_force(self.tmp_dir)

    def test_01_split_unicode_escapes_detected_and_fails(self):
        """Prove: a Markdown file containing a fake username represented only as

        split \\uXXXX escapes is detected and causes the publication gate to FAIL.
        """
        # Encode each character of the synthetic user into \uXXXX
        split_escapes = [f"\\u{ord(c):04x}" for c in SYNTHETIC_TARGET_USER]
        md_content = (
            "# Test Documentation\n\n"
            "Here is a tokenisation example:\n\n"
            "```text\n"
            'texts: [ ... " C", ":", "\\\\\\\\", "Users", "\\\\\\\\", '
            + ", ".join(f'"{esc}"' for esc in split_escapes)
            + ', "\\\\\\\\", ".d", "sh", ... ]\n'
            "```\n"
        )

        test_file = os.path.join(self.tmp_dir, "DOC.md")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(md_content)

        # 1. Direct scan_content verification
        violations = scan_content(md_content, "DOC.md", self.targets)
        self.assertTrue(len(violations) > 0, "Split unicode escapes must be detected")
        self.assertTrue(
            any(v["class"] == "winuser" and "split_unicode" in v["layer"] for v in violations),
            f"Expected winuser violation in split_unicode layer, got {violations}",
        )

        # 2. End-to-end verify_publication gate verification
        result = verify_publication(
            repo_root=self.tmp_dir,
            extra_literals={"winuser": [SYNTHETIC_TARGET_USER]},
        )
        self.assertEqual(result["verdict"], "FAIL", "Publication gate must FAIL CLOSED on split unicode escapes")
        self.assertTrue(result["violation_count"] >= 1)

    def test_02_synthetic_placeholders_pass(self):
        """Prove: replacing those fragments with synthetic placeholders causes PASS."""
        md_content = (
            "# Test Documentation\n\n"
            "Here is a tokenisation example with synthetic placeholders:\n\n"
            "```text\n"
            'texts: [ ... " C", ":", "\\\\\\\\", "Users", "\\\\\\\\", '
            '"<fragment-1>", "<fragment-2>", "<fragment-3>", "<fragment-4>", '
            '\\\\\\\\", ".d", "sh", ... ]\n'
            "```\n"
        )

        test_file = os.path.join(self.tmp_dir, "DOC.md")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(md_content)

        violations = scan_content(md_content, "DOC.md", self.targets)
        self.assertEqual(violations, [], f"Synthetic placeholders must not produce violations, got {violations}")

        result = verify_publication(
            repo_root=self.tmp_dir,
            extra_literals={"winuser": [SYNTHETIC_TARGET_USER]},
        )
        self.assertEqual(result["verdict"], "PASS", "Publication gate must PASS with synthetic placeholders")
        self.assertEqual(result["violation_count"], 0)

    def test_03_raw_seeded_private_literal_detected(self):
        """Prove: a raw seeded private literal is detected and causes FAIL."""
        content = (
            "# Research Notes\n\n"
            f"This session analyses corpus {SYNTHETIC_TARGET_PROJECT} in depth.\n"
        )
        test_file = os.path.join(self.tmp_dir, "NOTES.md")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(content)

        violations = scan_content(content, "NOTES.md", self.targets)
        self.assertTrue(len(violations) >= 1)
        self.assertTrue(any(v["class"] == "project" and v["layer"] == "raw_text" for v in violations))

        result = verify_publication(
            repo_root=self.tmp_dir,
            extra_literals={"project": [SYNTHETIC_TARGET_PROJECT]},
        )
        self.assertEqual(result["verdict"], "FAIL", "Publication gate must FAIL on raw seeded literal")

    def test_04_percent_encoded_and_html_entity_forms_detected(self):
        """Prove: percent-encoded and HTML-entity forms are detected and cause FAIL."""
        # 4a. Percent-encoded
        pct_encoded = "".join(f"%{b:02X}" for b in SYNTHETIC_TARGET_USER.encode("utf-8"))
        pct_content = f"Reference: https://example.local/query?u={pct_encoded}\n"

        pct_file = os.path.join(self.tmp_dir, "URL.txt")
        with open(pct_file, "w", encoding="utf-8") as f:
            f.write(pct_content)

        pct_violations = scan_content(pct_content, "URL.txt", self.targets)
        self.assertTrue(len(pct_violations) >= 1, "Percent-encoded literal must be detected")
        self.assertTrue(
            any("url_unquote" in v["layer"] or "percent" in v["layer"] for v in pct_violations),
            f"Expected percent/url layer detection, got {pct_violations}",
        )

        # 4b. HTML entities (hex and decimal)
        html_hex = "".join(f"&#x{ord(c):04x};" for c in SYNTHETIC_TARGET_USER)
        html_content = f"<html><body>User: {html_hex}</body></html>\n"

        html_file = os.path.join(self.tmp_dir, "PAGE.html")
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        html_violations = scan_content(html_content, "PAGE.html", self.targets)
        self.assertTrue(len(html_violations) >= 1, "HTML-entity encoded literal must be detected")
        self.assertTrue(
            any("html" in v["layer"] for v in html_violations),
            f"Expected html layer detection, got {html_violations}",
        )

    def test_05_output_does_not_reveal_private_literal(self):
        """Prove: test/log/report output does not reveal the private literal being tested."""
        split_escapes = [f"\\u{ord(c):04x}" for c in SYNTHETIC_TARGET_USER]
        md_content = f"Fragment: {', '.join(split_escapes)}"

        test_file = os.path.join(self.tmp_dir, "SECRET.md")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(md_content)

        # Capture both stdout and stderr during verification run
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()

        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            result = verify_publication(
                repo_root=self.tmp_dir,
                extra_literals={"winuser": [SYNTHETIC_TARGET_USER]},
            )

        captured_stdout = stdout_buf.getvalue()
        captured_stderr = stderr_buf.getvalue()
        result_json_str = str(result)

        # Assert private target value NEVER appears in stdout, stderr, or result structure
        self.assertNotIn(
            SYNTHETIC_TARGET_USER,
            captured_stdout,
            "Private target must never appear in stdout",
        )
        self.assertNotIn(
            SYNTHETIC_TARGET_USER,
            captured_stderr,
            "Private target must never appear in stderr",
        )
        self.assertNotIn(
            SYNTHETIC_TARGET_USER,
            result_json_str,
            "Private target must never appear in verifier result data",
        )


class TestGitMetadataGate(unittest.TestCase):
    """Regression tests for the Git commit-metadata publication gate.

    PRIVACY: fixtures use only synthetic identities, plus the PUBLIC allowed
    publication identity (GitHub noreply). Real private names/emails/usernames
    must never appear here or in any output.
    """

    # Synthetic PRIVATE identities for FAIL cases - never real values
    SYNTHETIC_PRIVATE_NAME = SYNTHETIC_TARGET_USER
    SYNTHETIC_PRIVATE_EMAIL = "synthetic-private-committer@example.invalid"

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_git_meta_")

    def tearDown(self):
        _rmtree_force(self.tmp_dir)

    def _git(self, *args, env_extra=None):
        env = dict(os.environ)
        env.update({
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "LC_ALL": "C",
        })
        if env_extra:
            env.update(env_extra)
        subprocess.run(
            ["git", "-C", self.tmp_dir] + list(args),
            check=True, capture_output=True, env=env,
        )

    def _init_repo(self, author_name, author_email, committer_name, committer_email, message="synthetic publication commit\n"):
        self._git("init", "-q", "-b", "main")
        with open(os.path.join(self.tmp_dir, "DOC.md"), "w", encoding="utf-8") as f:
            f.write("# Synthetic Publication\n\nClean placeholder documentation.\n")
        self._git("add", "DOC.md")
        self._git(
            "commit", "-q", "-m", message,
            env_extra={
                "GIT_AUTHOR_NAME": author_name,
                "GIT_AUTHOR_EMAIL": author_email,
                "GIT_COMMITTER_NAME": committer_name,
                "GIT_COMMITTER_EMAIL": committer_email,
            },
        )

    def test_01_private_committer_identity_fails(self):
        """Prove: private synthetic committer metadata causes the gate to FAIL."""
        self._init_repo(
            ALLOWED_PUBLICATION_NAME, ALLOWED_PUBLICATION_EMAIL,
            self.SYNTHETIC_PRIVATE_NAME, self.SYNTHETIC_PRIVATE_EMAIL,
        )
        result = verify_publication(repo_root=self.tmp_dir)
        self.assertEqual(result["verdict"], "FAIL", "Gate must FAIL CLOSED on private committer metadata")
        self.assertTrue(
            any(v["class"] == "git_committer_identity" for v in result["git_metadata_violations"]),
            f"Expected git_committer_identity violation, got {result['git_metadata_violations']}",
        )
        # Direct function-level assertion as well
        violations = verify_commit_metadata(repo_root=self.tmp_dir)
        self.assertTrue(any(v["class"] == "git_committer_identity" for v in violations))

    def test_02_private_author_identity_fails(self):
        """Prove: private synthetic author metadata causes the gate to FAIL."""
        self._init_repo(
            self.SYNTHETIC_PRIVATE_NAME, self.SYNTHETIC_PRIVATE_EMAIL,
            ALLOWED_PUBLICATION_NAME, ALLOWED_PUBLICATION_EMAIL,
        )
        result = verify_publication(repo_root=self.tmp_dir)
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(v["class"] == "git_author_identity" for v in result["git_metadata_violations"]),
            f"Expected git_author_identity violation, got {result['git_metadata_violations']}",
        )

    def test_03_noreply_metadata_passes(self):
        """Prove: the allowed public noreply identity for author+committer PASSES."""
        self._init_repo(
            ALLOWED_PUBLICATION_NAME, ALLOWED_PUBLICATION_EMAIL,
            ALLOWED_PUBLICATION_NAME, ALLOWED_PUBLICATION_EMAIL,
        )
        result = verify_publication(repo_root=self.tmp_dir)
        self.assertEqual(result["verdict"], "PASS", "Gate must PASS on allowed noreply metadata")
        self.assertEqual(result["git_metadata_violation_count"], 0)

    def test_04_private_literal_in_commit_metadata_fails(self):
        """Prove: a seeded private literal inside the commit message FAILs CLOSED
        even when both identities are the allowed noreply identity."""
        self._init_repo(
            ALLOWED_PUBLICATION_NAME, ALLOWED_PUBLICATION_EMAIL,
            ALLOWED_PUBLICATION_NAME, ALLOWED_PUBLICATION_EMAIL,
            message=f"session notes referencing corpus {SYNTHETIC_TARGET_PROJECT}\n",
        )
        result = verify_publication(
            repo_root=self.tmp_dir,
            extra_literals={"project": [SYNTHETIC_TARGET_PROJECT]},
        )
        self.assertEqual(result["verdict"], "FAIL")
        self.assertTrue(
            any(v["class"] == "git_metadata_private_literal" for v in result["git_metadata_violations"]),
            f"Expected git_metadata_private_literal violation, got {result['git_metadata_violations']}",
        )

    def test_05_metadata_output_does_not_reveal_private_identity(self):
        """Prove: gate output never reveals the tested private identity values."""
        self._init_repo(
            ALLOWED_PUBLICATION_NAME, ALLOWED_PUBLICATION_EMAIL,
            self.SYNTHETIC_PRIVATE_NAME, self.SYNTHETIC_PRIVATE_EMAIL,
        )
        stdout_buf = io.StringIO()
        stderr_buf = io.StringIO()
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            result = verify_publication(repo_root=self.tmp_dir)
        self.assertEqual(result["verdict"], "FAIL")
        captured = stdout_buf.getvalue() + stderr_buf.getvalue() + str(result)
        self.assertNotIn(self.SYNTHETIC_PRIVATE_NAME, captured)
        self.assertNotIn(self.SYNTHETIC_PRIVATE_EMAIL, captured)

    def test_06_non_git_directory_is_skipped(self):
        """Prove: a directory that is not a git repo yields no metadata violations
        (no commit to gate) while file scanning still applies."""
        violations = verify_commit_metadata(repo_root=self.tmp_dir)
        self.assertEqual(violations, [])


def main():
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    suite.addTests(loader.loadTestsFromTestCase(TestPublicationVerifier))
    suite.addTests(loader.loadTestsFromTestCase(TestGitMetadataGate))
    runner = unittest.TextTestRunner(verbosity=2)
    res = runner.run(suite)
    return 0 if res.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
