# DeepSeek Harness V4 Pro Gray-Test Long-Running Session — 2026-08-21

This repository contains a privacy-redacted DeepSeek Harness session captured during a
DeepSeek V4 Pro gray-test period on August 21, 2026.

The session represents a real-world long-running coding-agent workflow rather than a
synthetic benchmark. It spans 8 calendar days of wall-clock time and contains 25,464
events, 311 tool calls, 39 turns and 338 steps.

## What this artifact is

A client-side DeepSeek Harness session log (`session.jsonl.zstd`), converted into a
privacy-redacted research version. The original event structure is preserved exactly:

* same number of events (25,464 in, 25,464 out)
* same event order and same event-type sequence
* same JSON key structure and value types
* same tool-call / tool-result reference graph (0 broken links)
* same turn / step / session structure
* the concatenated-frame Zstandard container layout is preserved, so the artifact loads
  with the stock DeepSeek Harness session reader

## Potential uses

* DeepSeek Harness session compatibility testing
* session replay and migration testing
* long-running agent behavior research
* tool-use trajectory analysis
* historical model behavior analysis
* request/header and event-format research

## What it contains (client-observable)

| Field | Value |
| --- | --- |
| Session window (UTC) | 2026-08-20T22:45:01.987Z → 2026-08-28T20:42:39.045Z |
| Events | 25,464 |
| Requests (`request/header`) | 14 |
| Assistant messages | 328 |
| Tool calls / results | 311 / 311 |
| Turns / steps | 39 / 338 |
| Providers (client-visible) | `deepseek-official` (344), `session-title-first-prompt-llm` (1) |
| Models (client-visible) | `deepseek-v4-pro` (344), `deepseek-v4-flash` (3) |
| `reasoningEffort` | `max` (14) |
| Token totals | input 8,022,712 / output 626,882 / reasoning 170,160 / cache_read 196,450,048 |

All counts come from the redacted artifact itself and cover only what the client recorded.
See `stats.json` and `timeline.csv`.

## Scope and limits — please read

This artifact contains client-observable data only.

It does **NOT** prove or disprove any server-side model routing, distillation, shadow
traffic, checkpoint identity, or training behavior.

The client-visible provider/model identifiers recorded in the session are preserved in
the redacted artifact. That is a statement about what the client wrote to its own log —
nothing more. Opaque server-side behavior cannot be inferred from the client log alone.
No claim in this repository should be read as evidence about any model's identity,
lineage, or training data.

## Redaction approach

Sensitive identifiers have been deterministically pseudonymized where necessary to
preserve structural relationships. Secrets and directly identifying private information
have been removed.

The hard part of this artifact is **streaming tokenisation**. The persistence layer stores
streamed model output as many small fragments, so a sensitive value can be split across
fragments and never appear intact in any single JSON string — for example a three-character
user name arriving as three separate array elements, or a path broken at every separator.
A scanner that only examines one string at a time is blind to that.

The redactor therefore runs in two passes:

1. every event is redacted scalar-wise, and the streaming fragment groups are collected;
2. each streaming group is reassembled, the **joined** text is redacted, and the result is
   redistributed onto the original fragment positions.

The verifier performs the same kind of reconstruction independently, so the blind spot
cannot hide: it scans **25,464 serialized event lines + 1,000 reassembled streams**.
(Event lines are the redacted JSONL records as written; they are scanned verbatim, so the
reported unit count is event lines, not a recursive count of string scalars.)

Results:

* deterministic placeholders: the same original value always becomes the same placeholder
  (call ids are numbered from the value itself, so the assembled view and the reassembled
  streaming view agree)
* secrets are never mapped and never logged: they collapse to `<REDACTED_SECRET>` with no
  length or structure preserved
* environment structure is kept: `C:\Users\<USER>\Documents\...` rather than `<REDACTED>`,
  and distinct `<QQ_GROUP_001>`/`<QQ_GROUP_002>`/… rather than one merged label
* 657 streaming groups were rewritten, removing 557,578 characters of sensitive fragment
  content
* research material is preserved: provider, model, `reasoningEffort`, `maxTokens`,
  `contextWindow`, request/header structure, event types, tool schemas and names, reasoning
  text, assistant text, tool arguments and results, errors, HTTP status codes, timestamps,
  token usage, versions, public package names, hashes and commit ids

The original file name and SHA-256 are **not** included in `redaction-report.json`
(marked `source_fingerprint: "withheld"`), so this release cannot be trivially correlated
with the source log. Re-running the redactor with `--include-source-fingerprint` embeds
them.

Full rules: `REDACTION.md`. Machine-readable results: `redaction-report.json`.

## Semantic closure (identity beyond structured PII)

Structured identifiers were not the whole problem: the transcript also carried a private
naming corpus and a short user portrait. Both were handled in the private seed, so the
pipeline itself is unchanged.

### Private naming corpus

Two literals name the same private game-mod corpus, once in simplified and once in
traditional script. They appear as file and event names (for example analysis notes
and script/diagnostic file pairs), so they act as a private corpus fingerprint rather
than an ordinary personal name. Both map to **one** stable placeholder:

| Literal | Placeholder |
| --- | --- |
| simplified form | `<PRIVATE_PROJECT_001>` |
| traditional form | `<PRIVATE_PROJECT_001>` |

A third name in the same corpus is a distinct in-game character identity with a different
trajectory, so it keeps its own placeholder, `<PRIVATE_PROJECT_002>`. All three forms now
have **0** raw occurrences in the artifact.

### User portrait

The transcript contains a compact portrait of the user (preferred language, a
non-technical self-description, token-sensitivity, a preference for being asked before
long unattended runs, and a glossary of the user's own idioms). That is a behavioural
fingerprint: it is stable across platforms and is not required to interpret the agent's
behaviour. Only the identifying descriptors were generalised; the transcript structure,
the agent's responses and the surrounding technical content are untouched.

| Original descriptor class | Generalized to |
| --- | --- |
| academic/liberal-arts background | `非技术背景` |
| user portrait / user preferences headers | `协作背景` / `协作偏好` |
| collaboration notice header | `协作说明` |
| user-idiom list header | `常用表达` |

76 rewrites were applied. Deliberately **retained** because they carry no identity link
and are needed to read the session: the user's language preference, their idioms with
their meanings, and their stated working preferences about verification and rollback.

### Semantic verification

The independent verifier now enumerates the private literal classes from the seed
(`contact`, `group_name`, `project`, `winuser`) and asserts zero residue for each, plus
zero residue for the generalised profile phrases. A placeholder such as
`<PRIVATE_PROJECT_001>` is a placeholder and is never counted as residue.
## Files

| File | Description |
| --- | --- |
| `session.redacted.jsonl` | Redacted session, one JSON event per line (UTF-8) |
| `session.redacted.jsonl.zstd` | Same content as a concatenated-frame Zstandard container |
| `stats.json` | Objective client-observable statistics |
| `timeline.csv` | Per-event timeline (timestamp, turn, step, type, provider, model, tool, tokens) |
| `redaction-report.json` | Redaction + verification report, including `safe_to_publish` |
| `REDACTION.md` | Redaction policy, rules and known residuals |
| `scripts/redact_session.py` | The redaction program (generic; contains no real identifiers) |
| `scripts/verify_redaction.py` | Independent verifier, including cross-chunk reconstruction and repo-wide scan |
| `scripts/verify_publication.py` | Repository-wide publication privacy verifier with multi-layer decoding |
| `scripts/test_publication_verifier.py` | Synthetic regression tests for publication privacy gate |

### Reproducing

```bash
pip install zstandard
python scripts/redact_session.py \
  --source <session.jsonl.zstd> \
  --out-jsonl session.redacted.jsonl \
  --out-zstd  session.redacted.jsonl.zstd \
  --stats stats.json --report redaction-report.json --timeline timeline.csv \
  [--seed <private-seed.json>] [--mapping-out <private-mapping.json>] \
  [--include-source-fingerprint]

python scripts/verify_redaction.py \
  --source <session.jsonl.zstd> \
  --redacted-jsonl session.redacted.jsonl \
  --redacted-zstd  session.redacted.jsonl.zstd \
  [--seed <private-seed.json>] [--out-json verification.json]
```

The published `redact_session.py` is deliberately generic: it carries no site-specific
literals. Environment-specific values (account names, group names) are supplied at runtime
through a private seed file that is not part of this repository.

## Verification status

`scripts/verify_redaction.py` re-derives every check from the artifacts themselves and
shares no code with the redactor. Current result: **all checks PASS**
(see `redaction-report.json` → `verification`):

| Check | Result |
| --- | --- |
| JSONL parse (source and redacted) | PASS |
| Event count and event-type sequence | PASS |
| Tool call/result link graph | PASS |
| Zstandard roundtrip (byte-identical) | PASS |
| Credential scan | PASS (0 hits) |
| Windows username residue | PASS (0) |
| QQ id residue | PASS (0) |
| Raw call-id residue | PASS (0) |
| Private literal residue | PASS (0) |
| Cross-chunk reconstruction scan | PASS |
| Private literal classes (contact, group_name, project, winuser) | PASS (0 each) |
| Generalised profile-phrase residue | PASS (0) |
| Residual email / phone candidates | 0 / 0 |
| Publication privacy scan (all tracked repo files) | PASS |

## Defects found and fixed during independent review

For transparency, an independent review of an earlier draft of this artifact found real
problems that this version fixes. They are recorded here because they are instructive
about redacting tokenised streams:

1. **Call ids were never redacted.** The pattern `\bcall_[A-Za-z0-9]{4,}` could not match the
   real shape `call_00_<payload>`: `_` is a word character so `\b` never matched, and the
   character class excluded `_` even though the payload contains them. 16,762 call-id
   occurrences are redacted in this version.
2. **Values split across stream fragments escaped scalar redaction** — a user name arriving
   as three separate fragments, and paths with doubled escaping
   (`C:\\\\Users\\\\<name>`) that the earlier path pattern (allowing only one or two
   separators) never matched. Fixed by the stream reassembly pass and a separator pattern
   of one-or-more.
3. **A synthetic `data` key was added to events that had none**, and the session id in the
   header event was never redacted because only `data` was redacted rather than the whole
   event.
4. **Rule/placeholder interaction corrupted identifiers**: the QQ keyword rules could match
   the text `call` inside an already-emitted `call_<000040>` placeholder and allocate that
   number as a bogus account. Fixed by matching the pattern rules only on the unchanged runs
   between already-redacted regions.

## License / usage

Data is published for research and compatibility testing. No warranty of fitness. If you
believe a residual identifier is present, please open an issue and it will be removed.