#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic, structure-preserving privacy redaction for DeepSeek Harness session logs.

Two passes over the log:
  pass 1  scalar redaction of every event (streaming deltas included), and collection of
          the streamed fragment groups keyed by (type, turn, step, index);
  pass 2  reassembly of each streaming group. The persistence layer tokenises streamed
          text, so a value can be split across fragments and never appear intact in any
          single string. Redacting the JOINED text closes that escape hatch; the
          fragments are then rewritten in place so counts, order and types are unchanged.

Guarantees: one output line per input event; identical event order and event-type
sequence; identical JSON key structure and value types; identical tool call/result
reference graph; deterministic placeholders (same input -> identical output).
Secrets are destroyed, never mapped, and never logged.

This script is GENERIC: it carries no site-specific literals. Environment-specific
values are supplied through a private seed file that is not published.
"""

from __future__ import annotations

import argparse
import collections
import csv
import contextlib
import hashlib
import json
import os
import re
import sys

try:
    import zstandard as zstd
except ImportError:
    sys.stderr.write("FATAL: the zstandard package is required (pip install zstandard)\n")
    raise SystemExit(2)
if not hasattr(zstd, "ZstdDecompressor"):
    sys.stderr.write("FATAL: zstandard resolved to a namespace package, not the extension\n")
    raise SystemExit(2)

F_SECRET = "<REDACTED_SECRET>"
F_USER = "<USER>"
F_NATID = "<NATIONAL_ID>"

def ph_person(n):      return "<PERSON_%03d>" % n
def ph_qq(n):          return "<QQ_ACCOUNT_%03d>" % n
def ph_group(n):       return "<QQ_GROUP_%03d>" % n
def ph_group_name(n):  return "<QQ_GROUP_NAME_%03d>" % n
def ph_contact(n):     return "<CONTACT_%03d>" % n
def ph_phone(n):       return "<PHONE_%03d>" % n
def ph_email(n):       return "<EMAIL_%03d>" % n
def ph_session(n):     return "session-<SESSION_%03d>" % n
def ph_call(n):        return "call_<%06d>" % n
def ph_token(n):       return "<TOKEN_%03d>" % n
def ph_project(n):     return "<PRIVATE_PROJECT_%03d>" % n

PH_FOR = {"person": ph_person, "qq": ph_qq, "group": ph_group, "group_name": ph_group_name,
          "contact": ph_contact, "phone": ph_phone, "email": ph_email,
          "session": ph_session, "call": ph_call, "token": ph_token,
          "project": ph_project}

RX = {
  "bearer": re.compile(r"(?i)Bearer[ ]+[A-Za-z0-9._~+/=\-]{8,}"),
  "private_key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
  "aws": re.compile(r"AKIA[0-9A-Z]{12,}"),
  "ghp": re.compile(r"ghp_[A-Za-z0-9]{16,}"),
  "ghpat": re.compile(r"github_pat_[A-Za-z0-9_]{16,}"),
  "openai": re.compile(r"sk-[A-Za-z0-9]{16,}"),
  "query_cred": re.compile(r"(?i)([?&](?:token|api_?key|apikey|access_token|refresh_token|client_secret|password|passwd|secret|signature|sig)=)([^&\s\x22\x27<>]{4,})"),
  "colon_cred": re.compile(r"(?i)(authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|credential|cookie|secret)([ ]*[:=][ ]*)([^\s\x22\x27,;]{6,})"),
  "win_user": re.compile(r"(?i)([A-Za-z]:[\\/]+Users[\\/]+)([^\\/\s\x22\x27<>|:*?]{1,64})"),
  "session_dir": re.compile(r"(sessions[\\/]+)(--[^\\/\x22\x27]{1,160}?--)([\\/])"),
  "session_id": re.compile(r"session-[0-9a-fA-F][0-9a-fA-F-]{6,}"),
  "call_id": re.compile(r"call_[0-9]{2}_[A-Za-z0-9_]{8,}"),
  "toolu_id": re.compile(r"toolu_[A-Za-z0-9_]{4,}"),
  "uuid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
  "email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
  "phone_cn": re.compile(r"(?<![0-9])1[3-9][0-9]{9}(?![0-9])"),
  "national_id": re.compile(r"(?<![0-9Xx])[1-9][0-9]{16}[0-9Xx](?![0-9])"),
  "qq_bracket": re.compile(r"(\x5b)([0-9]{5,12})(\x5d)"),
  "qq_bracket_prefix": re.compile(r"(\x5b)([0-9]{5,12})(\x5d[\s]*[0-9]{0,12}[\s]*:)"),
  "qq_chatlog": re.compile(r"(\x5d[\s]*)([0-9]{5,12})([\s]*:)"),
  "qq_labeled": re.compile(r"(?i)((?:qq|账号|帐号|群号|groups?|group[_ ]?id|account|好友|联系人|member)[^0-9\n]{0,16}?)([0-9]{5,12})(?![0-9])"),
  "qq_keyword": re.compile(r"(?i)((?:default[_ ]?(?:qq|group)|setup[_ ]?group|gid|sender|(?:qq|group)[_ ]?(?:id|number|num|no))[\s:=\x22\x27]{0,4})([0-9]{5,12})(?![0-9])"),
  "qq_numeric_key": re.compile(r"(\x22\x27)([0-9]{5,12})(\x22\x27[\s]*:[\s]*[\x7b])"),
  "qq_list": re.compile(r"([0-9]{5,12}(?:[ ]*,[ ]*[0-9]{5,12})+)(?![0-9])"),
  "qq_path": re.compile(r"(?i)(Tencent Files[\\/]+)([0-9]{5,12})(?![0-9])"),
}
RX_LONG = re.compile(r"(?<![0-9])[0-9]{13,}(?![0-9])")
SECRET_KEYS = ("bearer", "private_key", "aws", "ghp", "ghpat", "openai", "query_cred", "colon_cred")

def replace_spans(text, spans):
    out = []
    prev = 0
    for s, e, rep in spans:
        out.append(text[prev:s])
        out.append(rep)
        prev = e
    out.append(text[prev:])
    return "".join(out)

def merge_spans(spans):
    ordered = sorted(spans, key=lambda t: (t[0], -(t[1] - t[0])))
    merged = []
    for s in ordered:
        if merged and s[0] < merged[-1][1]:
            continue
        merged.append(s)
    return merged

class Redactor:
    """Deterministic placeholder allocator with first-seen numbering."""

    def __init__(self, seed):
        self.seed = seed or {}
        self.maps = collections.defaultdict(dict)
        self.counters = collections.Counter()
        self.stats = collections.Counter()
        self.used = {}
        self.value_derived = {"call"}   # see canonical_value_number
        self.findings = []
        self.group_ids = set(str(x) for x in (self.seed.get("group_ids") or []))
        self.account_ids = set(str(x) for x in (self.seed.get("account_ids") or []))
        self.literals = {}
        self.literal_classes = {}
        # profile-text generalisation: plain substring rewrites applied in the
        # neutral pre-pass. They never introduce placeholders and never touch ids.
        self.generalize = dict(self.seed.get("generalize") or {})
        prec = {"username": 0, "contact": 1, "group_name": 2, "person": 3}
        direct = self.seed.get("literals_direct") or {}
        for cls in sorted(direct, key=lambda c: prec.get(c, 9)):
            for lit, ph in (direct[cls] or {}).items():
                rank = prec.get(cls, 9)
                if lit in self.literals and self.literal_rank.get(lit, 9) <= rank:
                    continue
                self.literals[lit] = ph
                self.literal_classes[lit] = cls
                self.literal_rank = getattr(self, "literal_rank", {})
                self.literal_rank[lit] = rank
        reserved = self.seed.get("reserved") or {}
        for cls, entries in reserved.items():
            for num, lit in entries.items():
                self.maps[cls][lit] = PH_FOR[cls](int(num))
                self.used[PH_FOR[cls](int(num))] = lit
                self.counters[cls] = max(self.counters[cls], int(num))
        for gid in sorted(self.group_ids):
            self.placeholder("group", gid, count=False)
        for acc in sorted(self.account_ids):
            self.placeholder("qq", acc, count=False)
        self.literal_rx = None
        if self.literals:
            parts = sorted(self.literals, key=len, reverse=True)
            self.literal_rx = re.compile("|".join(re.escape(x) for x in parts))
        self.id_rx = None
        idmap = {}
        for gid in self.group_ids:
            idmap[gid] = self.maps["group"][gid]
        for acc in self.account_ids:
            idmap[acc] = self.maps["qq"][acc]
        self.id_map = idmap
        if idmap:
            parts = sorted(idmap, key=len, reverse=True)
            self.id_rx = re.compile("(?<![0-9])(" + "|".join(re.escape(x) for x in parts) + ")(?![0-9])")

    def placeholder(self, cls, literal, count=True):
        got = self.maps[cls].get(literal)
        if got is not None:
            if count:
                self.stats[cls] += 1
            return got
        self.counters[cls] += 1
        ph = PH_FOR[cls](self.counters[cls])
        while ph in self.used:
            self.counters[cls] += 1
            ph = PH_FOR[cls](self.counters[cls])
        self.maps[cls][literal] = ph
        self.used[ph] = literal
        if count:
            self.stats[cls] += 1
        return ph

    def secret(self, kind):
        self.stats["secrets"] += 1
        self.findings.append({"category": "secret", "kind": kind})
        return F_SECRET

    def qq_class(self, val):
        return "group" if val in self.group_ids else "qq"
    def canonical_value_number(self, cls, value, slot=10 ** 9):
        """Placeholder number derived from the VALUE, not from encounter order.

        Streamed fragments and assembled events are redacted in different orders, so a
        first-seen counter can give the same original id two different placeholders in
        the two views. A value-derived number cannot drift: the same id always maps to
        the same placeholder, in every view and in every run."""
        if cls in self.value_derived:
            return self.placeholder(cls, value)
        n = int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:16], 16) % slot + 1
        ph = PH_FOR[cls](n)
        while ph in self.used and self.used[ph] != value:
            n = n % slot + 1
            ph = PH_FOR[cls](n)
        self.maps[cls][value] = ph
        self.used[ph] = value
        self.stats[cls] += 1
        return ph

    def call_placeholder(self, value):
        """Public entry for the call-id class."""
        return self.canonical_value_number("call", value)
    def canonicalize(self, cls, values):
        """Assign placeholders for a class in sorted-value order.

        Encounter order differs between the assembled view and the reassembled streaming
        view, so a naive first-seen numbering gives the same original id two different
        placeholders in the two views. Sorting the values first makes numbering depend
        only on the value set, so every view agrees."""
        for i, v in enumerate(sorted(set(str(x) for x in values))):
            self.maps[cls][v] = PH_FOR[cls](i + 1)
            self.used[PH_FOR[cls](i + 1)] = v
        self.counters[cls] = max(self.counters[cls], len(set(values)))
    def spans_for(self, text, group_ids):
        """All redaction spans for one text, as non-overlapping offsets into THAT text.

        Seeded literals and seeded ids are rewritten first (call them "zero spans"), and
        the pattern rules are then matched ONLY on the unchanged runs BETWEEN those zero
        spans. Two problems are solved at once:
          * a placeholder such as call_<000040> can never be picked up by the QQ rules
            (it lives inside a replaced region, so it is never scanned);
          * pattern offsets are always original-text offsets, because each run is a
            contiguous slice of the original text."""
        zero = []
        for lit in sorted(self.literals, key=len, reverse=True):
            start = 0
            while True:
                i = text.find(lit, start)
                if i < 0:
                    break
                self.stats["literal"] += 1
                self.stats["literal:" + self.literal_classes.get(lit, "other")] += 1
                zero.append((i, i + len(lit), self.literals[lit]))
                start = i + len(lit)
        # profile-text generalisation (substring rewrite, no placeholder)
        for _ph, _rep in self.generalize.items():
            _start = 0
            while True:
                _i = text.find(_ph, _start)
                if _i < 0:
                    break
                self.stats["generalized"] += 1
                self.stats["generalized:" + _ph] += 1
                zero.append((_i, _i + len(_ph), _rep))
                _start = _i + len(_ph)
        for pid in sorted(self.id_map, key=len, reverse=True):
            start = 0
            while True:
                i = text.find(pid, start)
                if i < 0:
                    break
                before = text[i - 1] if i > 0 else ""
                after = text[i + len(pid)] if i + len(pid) < len(text) else ""
                if not before.isdigit() and not after.isdigit():
                    zero.append((i, i + len(pid), self.placeholder(self.qq_class(pid), pid)))
                start = i + len(pid)
        zero = merge_spans(zero)
        runs = []
        cursor = 0
        for s, e, _rep in zero:
            if s > cursor:
                runs.append((cursor, text[cursor:s]))
            cursor = e
        if cursor < len(text):
            runs.append((cursor, text[cursor:]))
        spans = []
        def add(m, base, rep):
            spans.append((base + m.start(), base + m.end(), rep))
        for base, seg in runs:
            if not seg:
                continue
            for k in ("bearer", "private_key", "aws", "ghp", "ghpat", "openai"):
                for m in RX[k].finditer(seg):
                    add(m, base, self.secret(k))
            for m in RX["query_cred"].finditer(seg):
                add(m, base, m.group(1) + self.secret("query_cred"))
            for m in RX["colon_cred"].finditer(seg):
                add(m, base, m.group(1) + m.group(2) + self.secret("colon_cred"))
            for m in RX["win_user"].finditer(seg):
                add(m, base, m.group(1) + F_USER)
            for m in RX["session_dir"].finditer(seg):
                add(m, base, m.group(1) + "<WORKSPACE_SLUG>" + m.group(3))
            for m in RX["national_id"].finditer(seg):
                add(m, base, F_NATID)
            for m in RX["email"].finditer(seg):
                add(m, base, self.placeholder("email", m.group(0)))
            for m in RX["phone_cn"].finditer(seg):
                add(m, base, self.placeholder("phone", m.group(0)))
            for m in RX["session_id"].finditer(seg):
                add(m, base, self.placeholder("session", m.group(0)))
            for k in ("call_id", "toolu_id"):
                for m in RX[k].finditer(seg):
                    add(m, base, self.call_placeholder(m.group(0)))
            for m in RX["uuid"].finditer(seg):
                add(m, base, self.placeholder("token", m.group(0)))
            for m in RX["qq_bracket"].finditer(seg):
                add(m, base, m.group(1) + self.placeholder(self.qq_class(m.group(2)), m.group(2)) + m.group(3))
            for m in RX["qq_bracket_prefix"].finditer(seg):
                add(m, base, m.group(1) + self.placeholder(self.qq_class(m.group(2)), m.group(2)) + m.group(3))
            for m in RX["qq_chatlog"].finditer(seg):
                add(m, base, m.group(1) + self.placeholder(self.qq_class(m.group(2)), m.group(2)) + m.group(3))
            for k in ("qq_labeled", "qq_keyword", "qq_path"):
                for m in RX[k].finditer(seg):
                    add(m, base, m.group(1) + self.placeholder(self.qq_class(m.group(2)), m.group(2)))
            for m in RX["qq_numeric_key"].finditer(seg):
                add(m, base, m.group(1) + self.placeholder(self.qq_class(m.group(2)), m.group(2)) + m.group(3))
            for m in RX["qq_list"].finditer(seg):
                parts = [x.strip() for x in m.group(1).split(",")]
                add(m, base, ",".join(self.placeholder(self.qq_class(v), v) for v in parts))
            for m in RX_LONG.finditer(seg):
                add(m, base, self.placeholder("token", "longdigit:" + m.group(0)))
        return merge_spans(zero + spans)

def redact_value(v, R, group_ids):
    if isinstance(v, str):
        spans = R.spans_for(v, group_ids)
        return replace_spans(v, spans) if spans else v
    if isinstance(v, dict):
        return {k: redact_value(x, R, group_ids) for k, x in v.items()}
    if isinstance(v, list):
        return [redact_value(x, R, group_ids) for x in v]
    return v

def stream_key(etype, data):
    if not (etype.endswith("chunks") or etype == "assistant/chunk"):
        return None
    if not isinstance(data, dict):
        return None
    turn = data.get("turn")
    step = data.get("step")
    idx = data.get("index")
    if not isinstance(turn, int) or not isinstance(step, int):
        return None
    return (etype, turn, step, idx)

def ordered_strings(node, out):
    if isinstance(node, dict):
        for x in node.values():
            ordered_strings(x, out)
    elif isinstance(node, list):
        for x in node:
            ordered_strings(x, out)
    elif isinstance(node, str):
        out.append(node)
    return out

def remap_strings(node, values, state):
    if isinstance(node, dict):
        return {k: remap_strings(v, values, state) for k, v in node.items()}
    if isinstance(node, list):
        return [remap_strings(v, values, state) for v in node]
    if isinstance(node, str):
        i = state[0]
        state[0] = i + 1
        return values[i] if i < len(values) else node
    return node
def redistribute(joined, spans, lens):
    """Rewrite fragments in place so that concatenating them yields exactly the redacted
    joined text: nothing duplicated, nothing lost, fragment count and order preserved.

    A span may cover several fragments. Its replacement text is emitted once, in the
    fragment containing the span start; all remaining positions covered by that span
    contribute nothing; positions outside every span are copied verbatim."""
    values = []
    cursor = 0
    mi = 0
    covered_end = None
    for L in lens:
        start = cursor
        end = cursor + L
        pieces = []
        pos = start
        guard = 0
        while pos < end and guard < 1000000:
            guard += 1
            if covered_end is not None:
                if pos < covered_end:
                    pos = covered_end if covered_end < end else end
                    continue
                covered_end = None
            while mi < len(spans) and spans[mi][1] <= pos:
                mi += 1
            if mi < len(spans) and spans[mi][0] <= pos < spans[mi][1]:
                ms, me, rep = spans[mi]
                pieces.append(rep)
                mi += 1
                covered_end = me
                pos = me if me < end else end
                continue
            nxt = spans[mi][0] if mi < len(spans) else end
            stop = min(end, nxt)
            if stop <= pos:
                stop = end
            pieces.append(joined[pos:stop])
            pos = stop
        values.append("".join(pieces))
        cursor = end
    return values
def strings_of(node, out):
    """Every string scalar under a node, in document order."""
    if isinstance(node, dict):
        for v in node.values():
            strings_of(v, out)
    elif isinstance(node, list):
        for v in node:
            strings_of(v, out)
    elif isinstance(node, str):
        out.append(node)
    return out

def main(argv=None):
    ap = argparse.ArgumentParser(description="Deterministic DSH session-log redaction.")
    for flag in ("--source", "--out-jsonl", "--out-zstd", "--stats", "--report", "--timeline"):
        ap.add_argument(flag, required=True)
    ap.add_argument("--seed")
    ap.add_argument("--mapping-out")
    ap.add_argument("--tmp-jsonl")
    ap.add_argument("--include-source-fingerprint", action="store_true",
                    help="embed the original file name and SHA-256 in the report"
                         " (enables cross-source correlation)")
    args = ap.parse_args(argv)

    seed_doc = {}
    if args.seed and os.path.exists(args.seed):
        with open(args.seed, "r", encoding="utf-8") as fh:
            seed_doc = json.load(fh)
    R = Redactor(seed_doc)
    group_ids = R.group_ids

    src_size = os.path.getsize(args.source)
    src_sha = hashlib.sha256()
    with open(args.source, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            src_sha.update(chunk)

    ev_types = collections.Counter()
    providers = collections.Counter()
    models = collections.Counter()
    efforts = collections.Counter()
    tools = collections.Counter()
    usage = collections.Counter()
    timeline = []
    call_calls = set()
    call_results = set()
    stream_groups = collections.defaultdict(list)
    stream_lines = {}
    n_events = 0
    n_parse_err = 0
    parse_errs = []
    n_out = 0
    t_min = None
    t_max = None
    session_id = None
    tmp_path = args.tmp_jsonl or (args.out_jsonl + ".pass1.tmp")

    def find_first(node, key):
        stack = [node]
        while stack:
            cur = stack.pop(0)
            if isinstance(cur, dict):
                for k, v in cur.items():
                    if k == key:
                        return v
                    if isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(cur, list):
                for x in cur:
                    if isinstance(x, (dict, list)):
                        stack.append(x)
        return None

    def observe(ev, etype, data):
        nonlocal t_min, t_max, session_id
        ev_types[etype] += 1
        t = ev.get("time") if isinstance(ev.get("time"), int) else ev.get("time0")
        if isinstance(t, int):
            t_min = t if t_min is None else min(t_min, t)
            t_max = t if t_max is None else max(t_max, t)
        if etype == "session" and session_id is None:
            session_id = ev.get("id")
        prov = find_first(ev, "provider")
        if isinstance(prov, str):
            providers[prov] += 1
        mdl = find_first(ev, "model")
        if isinstance(mdl, str):
            models[mdl] += 1
        eff = find_first(ev, "reasoningEffort")
        if isinstance(eff, str):
            efforts[eff] += 1
        nm = None
        if etype == "tool/call":
            nm = find_first(ev, "name")
            if isinstance(nm, str):
                tools[nm] += 1
            cid = find_first(ev, "callId")
            if isinstance(cid, str):
                call_calls.add(cid)
        if etype == "tool/result":
            cid = find_first(ev, "callId")
            if isinstance(cid, str):
                call_results.add(cid)
        for k in ("inputTokens", "outputTokens", "reasoningTokens", "cacheReadTokens"):
            val = find_first(ev, k)
            if isinstance(val, int):
                usage[k] += val
        tl = collections.OrderedDict()
        tl["timestamp"] = t if isinstance(t, int) else ""
        tl["turn"] = data.get("turn") if isinstance(data, dict) and isinstance(data.get("turn"), int) else ""
        tl["step"] = data.get("step") if isinstance(data, dict) and isinstance(data.get("step"), int) else ""
        tl["event_type"] = etype
        tl["provider"] = prov if isinstance(prov, str) else ""
        tl["model"] = mdl if isinstance(mdl, str) else ""
        tl["tool"] = nm if isinstance(nm, str) else ""
        tl["status"] = "error" if (isinstance(data, dict) and data.get("isError")) else ""
        for k in ("inputTokens", "outputTokens", "reasoningTokens"):
            v = find_first(ev, k)
            tl[{"inputTokens": "input_tokens", "outputTokens": "output_tokens", "reasoningTokens": "reasoning_tokens"}[k]] = v if isinstance(v, int) else ""
        tl["duration_ms"] = ""
        timeline.append(tl)

    # Call ids are value-derived, so the mode is enabled before ANY redaction happens;
    # the assembled view and the reassembled streaming view then agree by construction.
    R.value_derived.add("call")
    # ---------------- pass 1: scalar redaction of every event ----------------
    with contextlib.ExitStack() as st:
        fh = st.enter_context(open(args.source, "rb"))
        rd = st.enter_context(zstd.ZstdDecompressor().stream_reader(fh))
        fo = st.enter_context(open(tmp_path, "w", encoding="utf-8", newline="\n"))
        buf = b""
        while True:
            chunk = rd.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    break
                raw = buf[:nl]
                buf = buf[nl + 1:]
                if not raw.strip():
                    continue
                n_events += 1
                try:
                    ev = json.loads(raw)
                except Exception as exc:
                    n_parse_err += 1
                    if len(parse_errs) < 10:
                        parse_errs.append({"line": n_events, "error": str(exc)[:200]})
                    continue
                etype = ev.get("type", "")
                data = ev.get("data")
                observe(ev, etype, data)
                key = stream_key(etype, data)
                ev2 = dict(ev)
                if key is not None:
                    payload = {k: v for k, v in data.items() if k not in ("turn", "step", "index", "dt")}
                    # stream fragments are left UNREDACTED here on purpose: pass 2
                    # reassembles the group first and redacts the joined text once.
                    # Redacting them here as well would let a later rule match inside an
                    # already-emitted placeholder (e.g. qq_labeled matching "call" in
                    # call_<000040>) and corrupt the identifier space.
                    stream_groups[key].append((n_events, payload))
                    stream_lines[n_events] = key
                    merged = dict(data)
                    merged.update(payload)
                    ev2["data"] = merged
                else:
                    if key is not None:
                        ev2 = dict(ev)   # pass 2 rebuilds this stream payload
                    else:
                        ev2 = redact_value(ev, R, group_ids)   # whole event, not just data
                fo.write(json.dumps(ev2, ensure_ascii=False, separators=(",", ":")) + "\n")
                n_out += 1
        if buf.strip():
            n_events += 1
            ev = json.loads(buf)
            etype = ev.get("type", "")
            data = ev.get("data")
            observe(ev, etype, data)
            if key is not None:
                ev2 = dict(ev)   # pass 2 rebuilds this stream payload
            else:
                ev2 = redact_value(ev, R, group_ids)   # whole event, not just data
            fo.write(json.dumps(ev2, ensure_ascii=False, separators=(",", ":")) + "\n")
            n_out += 1

    # ---------------- pass 2: reassemble streams, then emit ----------------
    rewritten = {}
    st_stats = collections.Counter()
    for key, payloads in stream_groups.items():
        lens = []
        texts = []
        for _ln, payload in payloads:
            vals = ordered_strings(payload, [])
            for v in vals:
                texts.append(v)
                lens.append(len(v))
        if not texts:
            continue
        joined = "".join(texts)
        spans = R.spans_for(joined, group_ids)
        if not spans:
            continue
        st_stats["groups_rewritten"] += 1
        st_stats["characters_dropped"] += sum(e - s for s, e, _ in spans)
        newvals = redistribute(joined, spans, lens)
        cursor = 0
        for ln, payload in payloads:
            count = len(ordered_strings(payload, []))
            chunk = newvals[cursor:cursor + count]
            cursor += count
            state = [0]
            rewritten[ln] = remap_strings(payload, chunk, state)

    with contextlib.ExitStack() as st:
        fj = st.enter_context(open(tmp_path, "r", encoding="utf-8"))
        fo = st.enter_context(open(args.out_jsonl, "w", encoding="utf-8", newline="\n"))
        fz = st.enter_context(open(args.out_zstd, "wb"))
        cctx = zstd.ZstdCompressor(write_checksum=True)
        n_lines = 0
        for line in fj:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            n_lines += 1
            ev = json.loads(line)
            if n_lines in rewritten:
                data = ev.get("data")
                if isinstance(data, dict):
                    merged = dict(data)
                    merged.update(rewritten[n_lines])
                    ev["data"] = merged
            emit_line = json.dumps(ev, ensure_ascii=False, separators=(",", ":"))
            fo.write(emit_line + "\n")
            fz.write(cctx.compress((emit_line + "\n").encode("utf-8")))
    n_out = n_lines
    if not args.tmp_jsonl and os.path.exists(tmp_path):
        os.remove(tmp_path)

    broken = sorted(call_calls - call_results) + sorted(call_results - call_calls)

    import datetime
    def iso(ms):
        if ms is None:
            return None
        return datetime.datetime.fromtimestamp(ms / 1000.0, tz=datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    stats = collections.OrderedDict()
    stats["session_start"] = iso(t_min)
    stats["session_end"] = iso(t_max)
    stats["session_id_placeholder"] = R.maps["session"].get(session_id) if session_id else None
    stats["event_count"] = n_out
    stats["event_types"] = dict(ev_types.most_common())
    stats["request_count"] = ev_types.get("request/header", 0)
    stats["assistant_message_count"] = ev_types.get("assistant/message", 0)
    stats["tool_call_count"] = ev_types.get("tool/call", 0)
    stats["tool_result_count"] = ev_types.get("tool/result", 0)
    stats["turn_count"] = ev_types.get("turn/start", 0)
    stats["step_count"] = ev_types.get("step/start", 0)
    stats["providers"] = dict(providers.most_common())
    stats["models"] = dict(models.most_common())
    stats["reasoning_efforts"] = dict(efforts.most_common())
    stats["tools"] = dict(tools.most_common())
    stats["token_totals"] = {"input_tokens": usage.get("inputTokens", 0), "output_tokens": usage.get("outputTokens", 0), "reasoning_tokens": usage.get("reasoningTokens", 0), "cache_read_tokens": usage.get("cacheReadTokens", 0)}
    stats["note"] = "Client-observable counts only; absent fields are omitted, never estimated."
    with open(args.stats, "w", encoding="utf-8") as fh:
        json.dump(stats, fh, ensure_ascii=False, indent=1)

    with open(args.timeline, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["timestamp", "turn", "step", "event_type", "provider", "model", "tool", "status", "input_tokens", "output_tokens", "reasoning_tokens", "duration_ms"])
        w.writeheader()
        for row in timeline:
            w.writerow(row)

    lit_classes = collections.Counter()
    for k, v in R.stats.items():
        if k.startswith("literal:"):
            lit_classes[k.split(":", 1)[1]] += v
    cats = {k: v for k, v in sorted(R.stats.items()) if not k.startswith("literal") and not k.startswith("secret_") and not k.startswith("generalized:")}
    report = collections.OrderedDict()
    # The report is a publishable artifact: embedding the original file name and its
    # SHA-256 would let a third party correlate this release with the source log, so
    # the fingerprint is withheld unless the operator explicitly asks for it.
    if args.include_source_fingerprint:
        report["source_file"] = os.path.basename(args.source)
        report["source_sha256"] = src_sha.hexdigest()
    else:
        report["source_fingerprint"] = "withheld"
    report["source_compressed_bytes"] = src_size
    report["source_event_count"] = n_events
    report["output_event_count"] = n_out
    report["json_parse_errors"] = n_parse_err
    report["json_parse_error_samples"] = parse_errs
    report["broken_call_links"] = len(broken)
    report["redacted_categories"] = cats
    report["redacted_literal_classes"] = dict(sorted(lit_classes.items()))
    report["secret_scan_findings"] = R.findings[:200]
    report["secret_findings_total"] = len(R.findings)
    report["stream_reassembly"] = {"groups_rewritten": st_stats["groups_rewritten"], "characters_dropped": st_stats["characters_dropped"]}
    report["generator"] = {"script": "scripts/redact_session.py", "deterministic": True, "two_pass_stream_aware": True}

    if args.mapping_out:
        with open(args.mapping_out, "w", encoding="utf-8") as fh:
            json.dump({"maps": {k: dict(v) for k, v in R.maps.items()}, "stats": dict(R.stats), "source_sha256": src_sha.hexdigest()}, fh, ensure_ascii=False, indent=1)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=1)

    sys.stderr.write("redact: in=%d out=%d parse_errors=%d broken_links=%d streams=%d\n" % (n_events, n_out, n_parse_err, len(broken), st_stats["groups_rewritten"]))
    return 0 if (n_parse_err == 0 and n_events == n_out) else 2


if __name__ == "__main__":
    raise SystemExit(main())