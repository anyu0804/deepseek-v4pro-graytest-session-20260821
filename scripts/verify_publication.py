#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Repository-wide publication privacy verifier.

Validates the complete tracked publishable repository against private seeded
literals, patterns, credentials, and identity-bearing context after decoding
and normalization across multiple representation layers:
  - raw UTF-8 text
  - HTML entity decoding (&...;, &#...;, &#x...;)
  - URL percent decoding (%XX)
  - Unicode/backslash escape decoding (\\uXXXX, \\\\uXXXX, \\UXXXXXXXX, \\xXX)
  - Split Unicode escape reconstruction (adjacent \\uXXXX fragments in arrays/lists)
  - Split percent-encoding reconstruction
  - Split HTML entity reconstruction
  - JSON string unescaping and key inspection
  - Windows path username segment validation
  - Raw call IDs and credentials detection

Fails CLOSED (exit 1) if any seeded private identifier or sensitive pattern
appears in any tracked publishable artifact after decoding.

CRITICAL: Reporting is value-free. Matched sensitive values are NEVER printed,
quoted, or logged in visible output or generated report files.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

CRED = {
    "bearer": re.compile(r"(?i)Bearer[ ]+[A-Za-z0-9._~+/=\-]{12,}"),
    "pem": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "aws": re.compile(r"AKIA[0-9A-Z]{16,}"),
    "ghp": re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    "ghpat": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    "openai": re.compile(r"sk-[A-Za-z0-9]{20,}"),
}

WINUSER_PATH = re.compile(r"(?i)[A-Za-z]:[\\/]{1,8}Users[\\/]{1,8}([^\\/\s\x22\x27<>|:*?]{1,64})")
RAW_CALL = re.compile(r"call[_:-][0-9]+[_:-][A-Za-z0-9_]{4,}")

SAFE_USER_PLACEHOLDERS = {
    "<user>",
    "<username>",
    "<fragment-1>",
    "<fragment-2>",
    "<fragment-3>",
    "<fragment-4>",
    "public",
    "default",
    "runner",
    "github",
}

DELIM_RX = re.compile(r"^[\s,\"\x27\[\]\(\)\\{}/:;-]*$")

# Allowed publication identity for this repository: the public GitHub noreply
# identity. Any other author/committer identity FAILS CLOSED. This is a public
# (non-private) identifier; private local identities are never allowed here.
ALLOWED_PUBLICATION_NAME = "anyu0804"
ALLOWED_PUBLICATION_EMAIL = "anyu0804@users.noreply.github.com"


def decode_unicode_escapes(text: str) -> str:
    """Decode \\uXXXX, \\\\uXXXX, and \\UXXXXXXXX sequences in text."""
    def _sub_u(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)

    def _sub_U(m: re.Match) -> str:
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)

    # Decode \U0000XXXX
    t1 = re.sub(r"(?:\\{1,4})U([0-9a-fA-F]{8})", _sub_U, text)
    # Decode \uXXXX
    return re.sub(r"(?:\\{1,4})u([0-9a-fA-F]{4})", _sub_u, t1)


def decode_split_unicode_escapes(text: str) -> List[str]:
    """Reconstruct adjacent \\uXXXX sequences separated only by delimiter syntax."""
    matches = list(re.finditer(r"(?:\\{1,4})u([0-9a-fA-F]{4})", text))
    if not matches:
        return []

    chains: List[List[re.Match]] = []
    current: List[re.Match] = [matches[0]]

    for m in matches[1:]:
        prev = current[-1]
        gap = text[prev.end():m.start()]
        if len(gap) <= 50 and DELIM_RX.match(gap):
            current.append(m)
        else:
            if len(current) > 1:
                chains.append(current)
            current = [m]
    if len(current) > 1:
        chains.append(current)

    reconstructed: List[str] = []
    for chain in chains:
        chars = "".join(chr(int(m.group(1), 16)) for m in chain)
        reconstructed.append(chars)
    return reconstructed


def decode_split_percent_escapes(text: str) -> List[str]:
    """Reconstruct adjacent %XX percent-encoded sequences separated by delimiters."""
    matches = list(re.finditer(r"%[0-9a-fA-F]{2}", text))
    if not matches:
        return []

    chains: List[List[re.Match]] = []
    current: List[re.Match] = [matches[0]]

    for m in matches[1:]:
        prev = current[-1]
        gap = text[prev.end():m.start()]
        if len(gap) <= 50 and DELIM_RX.match(gap):
            current.append(m)
        else:
            if len(current) > 1:
                chains.append(current)
            current = [m]
    if len(current) > 1:
        chains.append(current)

    reconstructed: List[str] = []
    for chain in chains:
        raw_bytes = bytes(int(m.group(0)[1:], 16) for m in chain)
        try:
            reconstructed.append(raw_bytes.decode("utf-8"))
        except UnicodeDecodeError:
            pass
    return reconstructed


def decode_split_html_entities(text: str) -> List[str]:
    """Reconstruct adjacent numeric HTML entities separated by delimiters."""
    matches = list(re.finditer(r"&#(?:x[0-9a-fA-F]{1,6}|[0-9]{1,7});", text, re.IGNORECASE))
    if not matches:
        return []

    chains: List[List[re.Match]] = []
    current: List[re.Match] = [matches[0]]

    for m in matches[1:]:
        prev = current[-1]
        gap = text[prev.end():m.start()]
        if len(gap) <= 50 and DELIM_RX.match(gap):
            current.append(m)
        else:
            if len(current) > 1:
                chains.append(current)
            current = [m]
    if len(current) > 1:
        chains.append(current)

    reconstructed: List[str] = []
    for chain in chains:
        decoded_chars = "".join(html.unescape(m.group(0)) for m in chain)
        reconstructed.append(decoded_chars)
    return reconstructed


def get_decoded_representations(text: str) -> List[Tuple[str, str]]:
    """Produce all normalized and decoded views of the text content."""
    reps: List[Tuple[str, str]] = []

    # 1. Raw text
    reps.append(("raw_text", text))

    # 2. HTML unescape
    unescaped_html = html.unescape(text)
    if unescaped_html != text:
        reps.append(("html_unescape", unescaped_html))

    # 3. URL unquote
    unquoted_url = urllib.parse.unquote(text)
    if unquoted_url != text:
        reps.append(("url_unquote", unquoted_url))

    # 4. Unicode escape decode
    decoded_unicode = decode_unicode_escapes(text)
    if decoded_unicode != text:
        reps.append(("unicode_escape", decoded_unicode))

    # 5. Combined: unquoted then unicode decoded
    if unquoted_url != text:
        combined = decode_unicode_escapes(unquoted_url)
        if combined != unquoted_url and combined != decoded_unicode:
            reps.append(("url_then_unicode", combined))

    # 6. Split unicode escapes reconstructed
    split_unicodes = decode_split_unicode_escapes(text)
    for i, s in enumerate(split_unicodes):
        reps.append((f"split_unicode_escape_{i}", s))

    # 7. Split percent escapes reconstructed
    split_percents = decode_split_percent_escapes(text)
    for i, s in enumerate(split_percents):
        reps.append((f"split_percent_{i}", s))

    # 8. Split HTML entities reconstructed
    split_html = decode_split_html_entities(text)
    for i, s in enumerate(split_html):
        reps.append((f"split_html_{i}", s))

    # 9. If JSON, parse and extract all keys and values
    if text.strip().startswith(("{", "[")):
        try:
            doc = json.loads(text)
            extracted: List[str] = []

            def _walk(obj: Any):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        extracted.append(str(k))
                        _walk(v)
                elif isinstance(obj, list):
                    for item in obj:
                        _walk(item)
                elif isinstance(obj, str):
                    extracted.append(obj)

            _walk(doc)
            reps.append(("json_decoded_tokens", "\n".join(extracted)))
        except Exception:
            pass

    return reps


def scan_content(
    content: str,
    filepath: str,
    literals_by_class: Dict[str, Set[str]],
    check_patterns: bool = True,
) -> List[Dict[str, str]]:
    """Scan content for seeded private literals and patterns across all decoded views.

    Returns a list of violations.
    CRITICAL: Never includes the private literal value in violation details.
    """
    violations: List[Dict[str, str]] = []
    views = get_decoded_representations(content)

    # 1. Check seeded private literals
    for target_class, targets in literals_by_class.items():
        for lit in sorted(targets, key=len, reverse=True):
            if not lit or len(lit.strip()) < 2:
                continue
            lit_lower = lit.lower()
            for layer_name, view_text in views:
                if lit in view_text or lit_lower in view_text.lower():
                    violations.append({
                        "file": filepath,
                        "class": target_class,
                        "layer": layer_name,
                        "type": "private_literal",
                    })
                    break  # One match per literal is enough

    # 2. Check regex patterns on raw and unicode-decoded views
    if check_patterns:
        # Check credentials
        for layer_name, view_text in [("raw_text", content), ("unicode_escape", decode_unicode_escapes(content))]:
            for cred_name, rx in CRED.items():
                if rx.search(view_text):
                    violations.append({
                        "file": filepath,
                        "class": f"credential:{cred_name}",
                        "layer": layer_name,
                        "type": "credential_pattern",
                    })

        # Check Windows user path leaks
        for m in WINUSER_PATH.finditer(content):
            user_seg = m.group(1).strip()
            if user_seg.lower() not in SAFE_USER_PLACEHOLDERS and not user_seg.startswith("<"):
                violations.append({
                    "file": filepath,
                    "class": "winuser_path",
                    "layer": "raw_text",
                    "type": "unredacted_path_segment",
                })

        # Check raw call IDs in documentation/metadata (excluding session.redacted.jsonl)
        if not filepath.endswith(".jsonl"):
            for m in RAW_CALL.finditer(content):
                violations.append({
                    "file": filepath,
                    "class": "raw_call_id",
                    "layer": "raw_text",
                    "type": "raw_call_id_residue",
                })

    return violations


def collect_target_literals(seed_path: Optional[str] = None, extra_literals: Optional[Dict[str, List[str]]] = None) -> Dict[str, Set[str]]:
    """Collect private target literals categorized by class.

    Includes current system environment username as 'winuser' if present.
    """
    targets: Dict[str, Set[str]] = {}

    def _add(cls: str, val: str):
        if not val or len(val.strip()) < 2:
            return
        targets.setdefault(cls, set()).add(val)

    # 1. Environment username
    env_user = os.environ.get("USERNAME") or os.environ.get("USER")
    if env_user and len(env_user) >= 2:
        _add("winuser", env_user)

    # 2. Seed file if provided
    if seed_path and os.path.exists(seed_path):
        try:
            with open(seed_path, "r", encoding="utf-8") as f:
                seed_doc = json.load(f)
            for cls, pairs in (seed_doc.get("literals_direct") or {}).items():
                for lit in (pairs or {}):
                    _add(cls, lit)
            for cls, reserved in (seed_doc.get("reserved") or {}).items():
                for lit in reserved.values():
                    _add(cls, lit)
            for acc in (seed_doc.get("account_ids") or []):
                _add("qq_account", str(acc))
            for gid in (seed_doc.get("group_ids") or []):
                _add("qq_group", str(gid))
            for phrase in (seed_doc.get("generalize") or {}):
                _add("generalize_phrase", phrase)
        except Exception as exc:
            sys.stderr.write(f"WARNING: Failed to parse seed file: {exc}\n")

    # 3. Extra literals
    if extra_literals:
        for cls, lits in extra_literals.items():
            for lit in lits:
                _add(cls, lit)

    return targets


def read_commit_metadata(repo_root: str, commit_ref: str = "HEAD") -> Optional[Dict[str, str]]:
    """Read author/committer identity and the raw commit object of a ref.

    Returns None when the target is not inside a git repository or has no
    commits — there is then no commit metadata to gate.
    """
    def _git(args: List[str]) -> Optional[str]:
        try:
            proc = subprocess.run(
                ["git", "-C", repo_root] + args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=True,
            )
            return proc.stdout
        except (OSError, subprocess.CalledProcessError):
            return None

    if _git(["rev-parse", "--show-toplevel"]) is None:
        return None
    out = _git(["log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce", commit_ref])
    if not out:
        return None
    parts = out.split("\x00")
    if len(parts) < 4:
        return None
    raw_object = _git(["cat-file", "commit", commit_ref]) or ""
    return {
        "author_name": parts[0].strip(),
        "author_email": parts[1].strip(),
        "committer_name": parts[2].strip(),
        "committer_email": parts[3].strip(),
        "raw_object": raw_object,
    }


def verify_commit_metadata(
    repo_root: str = ".",
    commit_ref: str = "HEAD",
    seed_path: Optional[str] = None,
    extra_literals: Optional[Dict[str, List[str]]] = None,
) -> List[Dict[str, str]]:
    """FAIL-CLOSED publication gate for the Git commit being published.

    Checks (value-free reporting, never prints the offending identity):
      1. author name/email must be exactly the allowed public noreply identity
      2. committer name/email must be exactly the allowed public noreply identity
      3. no seeded private literal (winuser, seed literals, extra literals) may
         appear anywhere in the commit metadata (identity lines, message, raw
         object headers), scanned across all decoded representation layers
    """
    meta = read_commit_metadata(repo_root, commit_ref)
    if meta is None:
        return []

    violations: List[Dict[str, str]] = []

    def _ident_violation(role: str, name: str, email: str) -> None:
        if email.strip().lower() != ALLOWED_PUBLICATION_EMAIL.lower() or name != ALLOWED_PUBLICATION_NAME:
            violations.append({
                "file": f"git:{commit_ref}",
                "class": f"git_{role}_identity",
                "layer": "commit_metadata",
                "type": "non_allowed_publication_identity",
            })

    _ident_violation("author", meta["author_name"], meta["author_email"])
    _ident_violation("committer", meta["committer_name"], meta["committer_email"])

    targets = collect_target_literals(seed_path=seed_path, extra_literals=extra_literals)
    for v in scan_content(meta["raw_object"], f"git:{commit_ref}", targets, check_patterns=False):
        if v["type"] == "private_literal":
            v = dict(v, **{"class": "git_metadata_private_literal"})
        violations.append(v)

    return violations


def get_tracked_files(repo_root: str) -> List[str]:
    """Get list of tracked files using git ls-files, or fallback to directory scan."""
    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        files = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        if files:
            return files
    except Exception:
        pass

    # Fallback: scan directory
    tracked = []
    for root, dirs, filenames in os.walk(repo_root):
        if ".git" in dirs:
            dirs.remove(".git")
        for fn in filenames:
            rel = os.path.relpath(os.path.join(root, fn), repo_root)
            tracked.append(rel.replace("\\", "/"))
    return tracked


def verify_publication(
    repo_root: str = ".",
    seed_path: Optional[str] = None,
    extra_literals: Optional[Dict[str, List[str]]] = None,
    out_json: Optional[str] = None,
    scan_jsonl: bool = True,
    check_git_metadata: bool = True,
) -> Dict[str, Any]:
    """Verify all tracked publishable text files in the repository.

    Additionally gates the Git commit metadata (author/committer identity and
    private-literal scan of the commit object) of the commit that would be
    published from this repository. FAIL CLOSED: returns verdict FAIL if any
    violation is detected.
    """
    targets = collect_target_literals(seed_path=seed_path, extra_literals=extra_literals)
    tracked_files = get_tracked_files(repo_root)

    # Exclude binary artifacts from raw text decoding
    binary_extensions = {".zstd", ".zip", ".tar", ".gz", ".png", ".jpg", ".exe"}

    scanned_files = []
    all_violations = []

    for rel_path in tracked_files:
        full_path = os.path.join(repo_root, rel_path)
        if not os.path.isfile(full_path):
            continue

        ext = os.path.splitext(rel_path)[1].lower()
        if ext in binary_extensions:
            continue

        if rel_path.endswith(".jsonl") and not scan_jsonl:
            continue

        scanned_files.append(rel_path)
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            violations = scan_content(content, rel_path, targets, check_patterns=True)
            if violations:
                all_violations.extend(violations)
        except Exception as exc:
            all_violations.append({
                "file": rel_path,
                "class": "file_read_error",
                "layer": "filesystem",
                "type": f"Error: {exc}",
            })

    verdict = "PASS" if not all_violations else "FAIL"

    git_violations: List[Dict[str, str]] = []
    if check_git_metadata:
        git_violations = verify_commit_metadata(
            repo_root=repo_root,
            commit_ref="HEAD",
            seed_path=seed_path,
            extra_literals=extra_literals,
        )
        if git_violations:
            all_violations = all_violations + git_violations
            verdict = "FAIL"

    result = {
        "verdict": verdict,
        "files_scanned_count": len(scanned_files),
        "files_scanned": scanned_files,
        "violation_count": len(all_violations),
        "violations": all_violations,
        "git_metadata_violation_count": len(git_violations),
        "git_metadata_violations": git_violations,
    }

    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)

    return result


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Publication privacy verifier for Git repositories.")
    ap.add_argument("--repo-root", default=".", help="Root of repository to scan")
    ap.add_argument("--seed", help="Path to private seed JSON file")
    ap.add_argument("--out-json", help="Path to output verification JSON report")
    ap.add_argument("--skip-jsonl", action="store_true", help="Skip scanning .jsonl files")
    args = ap.parse_args(argv)

    result = verify_publication(
        repo_root=args.repo_root,
        seed_path=args.seed,
        out_json=args.out_json,
        scan_jsonl=not args.skip_jsonl,
    )

    sys.stdout.write(f"Publication Verifier: {result['verdict']}\n")
    sys.stdout.write(f"Scanned files: {result['files_scanned_count']}\n")
    sys.stdout.write(
        f"Git metadata gate: "
        f"{'PASS' if result['git_metadata_violation_count'] == 0 else 'FAIL'} "
        f"({result['git_metadata_violation_count']} violation(s))\n"
    )

    if result["violations"]:
        sys.stderr.write(f"FAIL CLOSED: {len(result['violations'])} privacy/security violations detected:\n")
        for v in result["violations"]:
            sys.stderr.write(f"  - [{v['class']}] in {v['file']} (detected via {v['layer']})\n")
        return 1

    sys.stdout.write("All tracked repository files passed publication privacy verification.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
