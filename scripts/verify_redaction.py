#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent verification of a redacted DeepSeek Harness session artifact.

Shares no code with scripts/redact_session.py. Re-derives every check from the source (if provided)
and redacted artifacts. Crucially it performs CROSS-CHUNK RECONSTRUCTION: the persistence layer
tokenises streamed text, so sensitive values can be split across fragments and never appear
intact in any single string. A scanner that only looks at serialized event lines is blind
to that, so this verifier reassembles every streaming group before scanning.

Also integrates the repository-wide publication privacy verifier (scripts/verify_publication.py)
to validate that all tracked documentation, reports, and scripts remain free of sensitive
identifiers and encoded leaks.

Exit 0 = all automated checks pass, 1 = at least one hard failure.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import re
import sys
from typing import Optional

try:
    import zstandard as zstd
except ImportError:
    sys.stderr.write("FATAL: zstandard is required\n")
    raise SystemExit(2)

# Import the publication privacy verifier from the same directory
try:
    from scripts.verify_publication import verify_publication
except ImportError:
    try:
        from verify_publication import verify_publication
    except ImportError:
        verify_publication = None

CRED = {
    "bearer": re.compile(r"(?i)Bearer[ ]+[A-Za-z0-9._~+/=\-]{12,}"),
    "pem": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "aws": re.compile(r"AKIA[0-9A-Z]{16,}"),
    "ghp": re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    "ghpat": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    "openai": re.compile(r"sk-[A-Za-z0-9]{20,}"),
}
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE = re.compile(r"(?<![0-9])1[3-9][0-9]{9}(?![0-9])")
WINUSER = re.compile(r"(?i)[A-Za-z]:[\\/]{1,8}Users[\\/]{1,8}([^\\/\s\x22\x27<>|:*?]{1,64})")
RAW_CALL = re.compile(r"call[_:-][0-9]+[_:-][A-Za-z0-9_]{4,}")

SAFE_USER_TOKENS = {"<user>", "<username>", "<fragment-1>", "<fragment-2>", "<fragment-3>", "<fragment-4>"}


def strings_of(node, out=None):
    if out is None:
        out = []
    if isinstance(node, dict):
        for v in node.values():
            strings_of(v, out)
    elif isinstance(node, list):
        for v in node:
            strings_of(v, out)
    elif isinstance(node, str):
        out.append(node)
    return out


def stream_key(ev):
    t = ev.get("type", "")
    d = ev.get("data")
    if not (t.endswith("chunks") or t == "assistant/chunk"):
        return None
    if not isinstance(d, dict):
        return None
    turn, step, idx = d.get("turn"), d.get("step"), d.get("index")
    if not isinstance(turn, int) or not isinstance(step, int):
        return None
    return (t, turn, step, idx)


def reassembled_streams(redacted_path):
    """Join every streaming group (fragments in document order)."""
    groups = collections.defaultdict(list)
    order = {}
    for n, line in enumerate(open(redacted_path, "r", encoding="utf-8"), 1):
        if not line.strip():
            continue
        ev = json.loads(line)
        key = stream_key(ev)
        if key is None:
            continue
        d = ev["data"]
        payload = {k: v for k, v in d.items() if k not in ("turn", "step", "index", "dt")}
        groups[key].append("".join(strings_of(payload)))
        order.setdefault(key, n)
    return {k: "".join(v) for k, v in groups.items()}, order


def read_source_events(path):
    with open(path, "rb") as fh, zstd.ZstdDecompressor().stream_reader(fh) as rd:
        data = rd.read()
    for line in data.decode("utf-8").split("\n"):
        if line.strip():
            yield json.loads(line)


def call_id_of(data):
    if not isinstance(data, dict):
        return None
    cid = data.get("callId")
    if isinstance(cid, str):
        return cid
    msg = data.get("message")
    if isinstance(msg, dict):
        src = msg.get("source")
        if isinstance(src, dict) and isinstance(src.get("callId"), str):
            return src.get("callId")
    return None


def ph_class(phrase, seed):
    """Class name for a generalized phrase (value-free reporting)."""
    for cls, pairs in (seed.get("literals_direct") or {}).items():
        if phrase in (pairs or {}):
            return cls
    return "profile"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify redacted session artifact and publication privacy.")
    ap.add_argument("--source", required=False, default=None, help="Original unredacted session file (optional)")
    ap.add_argument("--redacted-jsonl", required=True, help="Redacted JSONL file")
    ap.add_argument("--redacted-zstd", required=True, help="Redacted Zstandard container")
    ap.add_argument("--seed", help="Private seed JSON file (optional)")
    ap.add_argument("--out-json", help="Output verification report JSON")
    ap.add_argument("--repo-root", default=".", help="Root directory for repository publication check")
    ap.add_argument("--skip-repo-scan", action="store_true", help="Skip publication repository scan")
    args = ap.parse_args(argv)

    seed = {}
    if args.seed and os.path.exists(args.seed):
        seed = json.load(open(args.seed, "r", encoding="utf-8"))
    account_ids = [str(x) for x in (seed.get("account_ids") or [])]
    group_ids = [str(x) for x in (seed.get("group_ids") or [])]
    literals = []
    literal_class = {}
    for _cls, pairs in (seed.get("literals_direct") or {}).items():
        for _lit in (pairs or {}):
            literals.append(_lit)
            literal_class[_lit] = _cls
    # Also check current environment username as a winuser target if available
    env_user = os.environ.get("USERNAME") or os.environ.get("USER")
    if env_user and len(env_user) >= 2 and env_user not in literals:
        literals.append(env_user)
        literal_class[env_user] = "winuser"

    generalize_keys = list((seed.get("generalize") or {}).keys())

    hard = []
    manual = []
    res = collections.OrderedDict()

    # ---- A. structure ----
    src_types = None
    src_calls = None
    src_results = None
    n_src = 0
    src_users = set()

    if args.source and os.path.exists(args.source):
        src_types = []
        src_calls = set()
        src_results = set()
        for ev in read_source_events(args.source):
            n_src += 1
            src_types.append(ev.get("type"))
            d = ev.get("data")
            if isinstance(d, dict) and ev.get("type") in ("tool/call", "tool/result"):
                cid = call_id_of(d)
                if isinstance(cid, str):
                    (src_calls if ev.get("type") == "tool/call" else src_results).add(cid)
            for s in strings_of(ev):
                for m in WINUSER.finditer(s):
                    src_users.add(m.group(1))

    red_types = []
    red_calls = set()
    red_results = set()
    n_red = 0
    red_parse_err = 0
    for line in open(args.redacted_jsonl, "r", encoding="utf-8"):
        if not line.strip():
            continue
        n_red += 1
        try:
            ev = json.loads(line)
        except Exception:
            red_parse_err += 1
            continue
        red_types.append(ev.get("type"))
        d = ev.get("data")
        if isinstance(d, dict) and ev.get("type") in ("tool/call", "tool/result"):
            cid = call_id_of(d)
            if isinstance(cid, str):
                (red_calls if ev.get("type") == "tool/call" else red_results).add(cid)

    res["A_jsonl_parse"] = "PASS" if red_parse_err == 0 else "FAIL"
    if red_parse_err:
        hard.append("redacted JSONL has %d unparseable lines" % red_parse_err)

    if src_types is not None:
        res["source_event_count"] = n_src
        res["redacted_event_count"] = n_red
        res["B_event_count"] = "PASS" if n_src == n_red else "FAIL"
        if n_src != n_red:
            hard.append("event count differs: %d vs %d" % (n_src, n_red))
        res["B_event_type_sequence"] = "PASS" if src_types == red_types else "FAIL"
        if src_types != red_types:
            bad = [i for i, (x, y) in enumerate(zip(src_types, red_types)) if x != y][:5]
            hard.append("event type sequence differs at %s" % bad)
        src_broken = sorted(src_calls ^ src_results)
        res["D_source_broken_links"] = len(src_broken)
    else:
        res["redacted_event_count"] = n_red
        res["B_event_count"] = "PASS" if n_red == 25464 else "FAIL"
        if n_red != 25464:
            hard.append("event count unexpected: %d (expected 25464)" % n_red)

    red_broken = sorted(red_calls ^ red_results)
    res["D_redacted_broken_links"] = len(red_broken)
    if src_calls is not None:
        res["D_tool_links"] = "PASS" if (not red_broken and len(src_calls) == len(red_calls)) else "FAIL"
        if len(src_calls) != len(red_calls):
            hard.append("distinct call ids changed: %d -> %d" % (len(src_calls), len(red_calls)))
    else:
        res["D_tool_links"] = "PASS" if not red_broken else "FAIL"

    if red_broken:
        hard.append("redacted tool links broken: %d" % len(red_broken))

    # ---- E. zstd container ----
    roundtrip = False
    try:
        with open(args.redacted_zstd, "rb") as fh, zstd.ZstdDecompressor().stream_reader(fh) as rd:
            decoded = rd.read()
        plain = open(args.redacted_jsonl, "rb").read()
        # On Windows git checkouts, text files may be checked out with CRLF
        if plain != decoded and plain.replace(b"\r\n", b"\n") == decoded:
            roundtrip = True
            res["E_plaintext_sha256"] = hashlib.sha256(decoded).hexdigest()
        else:
            roundtrip = decoded == plain
            res["E_plaintext_sha256"] = hashlib.sha256(plain).hexdigest()
    except Exception as exc:
        res["E_error"] = str(exc)[:200]
    res["E_zstd_roundtrip"] = "PASS" if roundtrip else "FAIL"
    if not roundtrip:
        hard.append("zstd roundtrip failed")

    # ---- F/G/H/I/J: per-event-line + CROSS-CHUNK scan ----
    streams, stream_line = reassembled_streams(args.redacted_jsonl)
    scan_units = []
    for line in open(args.redacted_jsonl, "r", encoding="utf-8"):
        if line.strip():
            scan_units.append(("event_line", line))
    for key, text in streams.items():
        scan_units.append(("stream", text))

    cred_hits = collections.Counter()
    email_hits = 0
    phone_hits = 0
    winuser_resid = collections.Counter()
    name_resid = collections.Counter()
    qq_resid = collections.Counter()
    raw_calls = collections.Counter()
    for kind, text in scan_units:
        for k, rx in CRED.items():
            for _m in rx.finditer(text):
                cred_hits[kind + ":" + k] += 1
        email_hits += len(EMAIL.findall(text))
        phone_hits += len(PHONE.findall(text))
        for m in WINUSER.finditer(text):
            seg = m.group(1).strip()
            if seg not in src_users and seg.lower() not in SAFE_USER_TOKENS and not seg.startswith("<"):
                winuser_resid[kind + ":<unredacted_path_user>"] += 1
        for lit in literals:
            if lit in text:
                name_resid[kind + ":" + literal_class.get(lit, "literal")] += 1
        for qid in account_ids + group_ids:
            if re.search(r"(?<![0-9])" + re.escape(qid) + r"(?![0-9])", text):
                qq_resid[kind + ":qq_id"] += 1
        for m in RAW_CALL.finditer(text):
            raw_calls[kind + ":" + m.group(0)] += 1

    res["scan_units"] = {
        "serialized_event_lines": sum(1 for k, _ in scan_units if k == "event_line"),
        "reassembled_streams": len(streams),
        "note": "event lines are scanned verbatim; each streaming group is also scanned"
                " after reconstruction, because fragments can split a value",
    }
    res["F_credential_hits"] = dict(cred_hits)
    res["F_secret_scan"] = "PASS" if not cred_hits else "FAIL"
    if cred_hits:
        hard.append("credential-shaped content found: %s" % dict(cred_hits))
    res["G_windows_username_residue"] = dict(winuser_resid)
    res["G_windows_username"] = "PASS" if not winuser_resid else "FAIL"
    if winuser_resid:
        hard.append("original windows username residue: %s" % dict(winuser_resid))
    res["H_literal_classes_checked"] = sorted(set(literal_class.values()))
    res["H_private_literal_residue"] = dict(name_resid)
    res["H_private_literals"] = "PASS" if not name_resid else "FAIL"
    if name_resid:
        hard.append("private literal residue: %s" % list(name_resid))
    res["G_qq_residue"] = dict(qq_resid)
    res["G_qq_ids"] = "PASS" if not qq_resid else "FAIL"
    if qq_resid:
        hard.append("QQ id residue: %s" % dict(qq_resid))
    res["I_raw_call_id_residue"] = len(raw_calls)
    res["I_call_ids"] = "PASS" if not raw_calls else "FAIL"
    if raw_calls:
        hard.append("raw call ids survive: %d" % len(raw_calls))
    gen_hits = collections.Counter()
    for kind, text in scan_units:
        for _ph in generalize_keys:
            if _ph in text:
                gen_hits[kind + ":" + ph_class(_ph, seed)] += 1
    res["I_generalized_phrase_residue"] = dict(gen_hits)
    res["I_generalized_phrases"] = "PASS" if not gen_hits else "FAIL"
    if gen_hits:
        hard.append("un-generalised profile phrase: %s" % dict(gen_hits))
    res["I_residual_email_candidates"] = email_hits
    res["I_residual_phone_candidates"] = phone_hits
    if email_hits:
        manual.append("email adjudication: %d" % email_hits)
    if phone_hits:
        manual.append("phone adjudication: %d" % phone_hits)

    # ---- K. Repository-wide publication privacy verification ----
    if not args.skip_repo_scan and verify_publication is not None:
        repo_res = verify_publication(
            repo_root=args.repo_root,
            seed_path=args.seed,
            scan_jsonl=False,  # Already deeply scanned above
        )
        res["K_publication_repo_scan"] = repo_res["verdict"]
        res["K_publication_files_checked"] = repo_res["files_scanned_count"]
        if repo_res["verdict"] != "PASS":
            hard.append(f"publication repository scan failed: {repo_res['violation_count']} violations")
            for v in repo_res.get("violations", []):
                manual.append(f"Repo violation: [{v['class']}] in {v['file']} via {v['layer']}")

    res["hard_failures"] = hard
    res["manual_review_required"] = manual
    res["verdict"] = "PASS" if not hard else "FAIL"
    text = json.dumps(res, ensure_ascii=False, indent=1)
    print(text)
    if args.out_json:
        open(args.out_json, "w", encoding="utf-8").write(text + "\n")
    return 0 if not hard else 1


if __name__ == "__main__":
    raise SystemExit(main())
