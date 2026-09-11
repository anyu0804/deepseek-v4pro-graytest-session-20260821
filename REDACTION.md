# Redaction Policy and Rules

This document describes how `session.redacted.jsonl` was produced from the original
DeepSeek Harness session log. It contains **no value → placeholder mapping** and **no
original identifiers of any kind**.

## Principles

1. **Structure over deletion.** Redaction rewrites string scalars only. Keys, ordering,
   types, event counts and references are preserved, so the artifact still replays.
2. **Deterministic pseudonyms.** The same original value always maps to the same
   placeholder, in every view and every run. Call ids are numbered from the value itself
   (a hash-derived slot), because the assembled view and the reassembled streaming view are
   processed in different orders and a first-seen counter would drift between them.
3. **Secrets are destroyed, not pseudonymized.** A credential becomes
   `<REDACTED_SECRET>` with no length, prefix or structure preserved, and is never logged.
4. **Environment shape is research data.** Paths keep their directory structure with only
   the user segment replaced; distinct private groups keep distinct labels.
5. **Never over-delete research material.** Provider, model, reasoning, tool schemas,
   timings and errors are kept unless they contain private data.

## The tokenisation problem (why there are two passes)

DeepSeek Harness stores streamed output as many small fragments. A sensitive value can be
split across fragments and therefore never appear intact in any single JSON string. Real
examples observed in this log:

```text
texts: [ ... " C", ":", "\\\\", "Users", "\\\\", "<fragment-1>", "<fragment-2>", "<fragment-3>", "\\\\", ".d", "sh", ... ]
```

Scanning one scalar at a time cannot see the user name here. Therefore:

* **Pass 1** redacts every event scalar-wise (except grouped stream payloads, which pass 2
  owns) and collects the streaming fragment groups keyed by (type, turn, step, index).
* **Pass 2** reassembles each group, redacts the **joined** text, and redistributes the
  redacted characters back onto the original fragment positions. Fragment count, event
  order and value types are unchanged.

Related trap: pattern rules are matched only on the **unchanged runs between already-redacted
regions**. Otherwise a rule can match the text `call` inside an emitted `call_<000040>`
placeholder and allocate `000040` as a bogus account, corrupting the identifier space.

## Placeholder formats

| Category | Placeholder | Notes |
| --- | --- | --- |
| Windows user segment | `<USER>` | `C:\Users\<X>\...` → `C:\Users\<USER>\...` |
| Session directory slug | `<WORKSPACE_SLUG>` | encoded `sessions\--…--\` segment |
| Person name | `<PERSON_NNN>` | one distinct placeholder per distinct person |
| Contact / nickname | `<CONTACT_NNN>` | one per distinct contact |
| Private naming corpus | `<PRIVATE_PROJECT_NNN>` | one stable placeholder per corpus entity; simplified and traditional spellings of the same entity share it |
| QQ account | `<QQ_ACCOUNT_NNN>` | stable per account |
| QQ group id | `<QQ_GROUP_NNN>` | one per group, relationships preserved |
| QQ group name | `<QQ_GROUP_NAME_NNN>` | one per distinct group name |
| Phone | `<PHONE_NNN>` | |
| Email | `<EMAIL_NNN>` | |
| National id | `<NATIONAL_ID>` | |
| Session id | `session-<SESSION_NNN>` | prefix kept |
| Tool call id | `call_<NNNNNN>` | value-derived; call ↔ result references stay consistent |
| Generic internal identifier | `<TOKEN_NNN>` | UUIDs and other opaque internal tokens |
| Secret | `<REDACTED_SECRET>` | never mapped, never logged |

Deterministic numbering is what preserves reference integrity: because a `tool/call` and
its `tool/result` carry the same original id, they receive the same placeholder, and the
verifier confirms the pairing graph is unchanged.

## What is redacted

* **Environment identity** — the Windows user segment in paths. The pattern tolerates
  arbitrarily deep escaping (`[\\/]+`), because code quoted inside the transcript escapes
  separators repeatedly; the earlier one-or-two-separator pattern missed
  `C:\\\\Users\\\\<name>`.
* **Personal names, nicknames, contact labels** — supplied through a private seed file and
  replaced in a single longest-match pass.
* **QQ identifiers** — accounts, group ids and group names, in every syntactic position
  observed: labelled text (`群号 …`), config fields (`"gid": N`, `"sender": N`,
  `DEFAULT_GROUP = N`), JSON object keys (`"<N>": {`), unquoted object keys, bracketed
  chat-log prefixes, CSV argument lists (`--groups 'a,b,c'`), path components
  (`Tencent Files\<account>\`), and any bare occurrence of a seeded id.
* **Contact data** — email addresses, mainland-China mobile numbers, 18-character national
  ids.
* **Structured identifiers** — session ids, call ids, message ids, UUIDs and other opaque
  internal tokens. The session id lives in the header event's top-level `id` field, which is
  why the whole event is redacted rather than only its `data`.
* **Credentials** — `Bearer` tokens, PEM private-key blocks, `AKIA…` / `ghp_…` /
  `github_pat_…` / `sk-…` style keys, URL query credentials and `key: value` /
  `key = value` credential assignments. In assignments only the value is replaced; the key
  name is kept so the schema stays readable.

## Semantic closure: naming corpus and user portrait

### Private naming corpus

The transcript references a private game-mod corpus by name, in both simplified and
traditional script, as file and event names. These are treated as private corpus
identifiers (class `project`), not as ordinary personal names, because they name the
corpus rather than a private individual. Simplified and traditional spellings of the same
entity must resolve to **one** placeholder so the relationship stays readable:

```text
simplified spelling  -> <PRIVATE_PROJECT_001>
traditional spelling -> <PRIVATE_PROJECT_001>
distinct in-corpus character identity -> <PRIVATE_PROJECT_002>
```

The literal list lives in the private seed and is injected before the pipeline runs; the
published script never contains it.

### User portrait

A compact portrait of the user appears in the transcript (non-technical self-description,
preference statements, and a glossary of the user's own idioms). Its headers and the
self-description are a behavioural fingerprint that is stable across platforms, so those
descriptors are generalised through a `generalize` map in the private seed:

```text
generalize: { "<original descriptor>": "<neutral descriptor>", ... }
```

Generalisation is a substring rewrite applied in the neutral pre-pass. It creates no
placeholder, touches no identifier, and leaves the JSON schema, event count and stream
reconstruction untouched. 76 rewrites were applied.

**Retained on purpose** (no identity link, needed to read the session): the user's
language preference, their idioms together with their meanings, and their stated working
preferences about verification and rollback.
## What is deliberately preserved

provider, model, `reasoningEffort`, `maxTokens`, `contextWindow`, request/header
structure, event types, sequence numbers and timestamps, public DSH agent system prompt
rules, tool schemas and tool names, tool arguments, tool results, reasoning text, assistant
text, error messages and codes, HTTP status codes, token usage, latencies, version numbers,
public npm package names, public file hashes / SHA256 / commit ids, and the public workspace
path of the DeepSeek Harness repository.

## Known, accepted residuals

* **Two long digit runs** remain because they are fragments of pnpm integrity hashes inside
  public package directory names (`@deepseek-ai+dsh-commands@0_<hash>`). They are not
  secrets and carry no identity.
* Public identifiers are not treated as private: loopback addresses (`127.0.0.1`,
  `localhost`), public registry URLs, public documentation links, and DeepSeek/GitHub/npm
  domains. All personal email addresses are redacted regardless of domain.
* **High-entropy strings are classified, not blanket-deleted.** SHA-256 digests, git hashes,
  UUIDs, package integrity hashes, call ids and session ids are legitimate and were reviewed
  individually; only credential-shaped material is destroyed.
* Group names are treated as private: the group names in this log became
  `<QQ_GROUP_NAME_NNN>`.

## Source fingerprint

`redaction-report.json` does **not** contain the original file name or its SHA-256; it
records `source_fingerprint: "withheld"`. Publishing them would let a third party correlate
this release with the source log. Pass `--include-source-fingerprint` to embed them.

## Reproducibility

`scripts/redact_session.py` is streaming (one JSONL line in memory at a time), reads and
writes the multi-frame Zstandard container format, and fails loudly (non-zero exit) on any
parse error or event-count mismatch. For a fixed input and seed it is deterministic and
re-runnable.

Environment-specific literals are **not** in the published script; they are supplied at
runtime through a private seed file that is never published, which is why the published
script can be audited without exposing any original identifier.

`scripts/verify_redaction.py` is independent: it re-derives all checks from the source and
redacted artifacts, shares no code with the redactor, and reassembles every streaming
fragment group before scanning — a scanner that only looks at serialized event lines
cannot see split values. Scan units are reported as
`25,464 serialized event lines + 1,000 reassembled streams`.

The verifier enumerates the private literal classes directly from the seed
(`contact`, `group_name`, `project`, `winuser`) and requires zero residue for each, plus
zero residue for the generalised profile phrases. Placeholders such as
`<PRIVATE_PROJECT_001>` are placeholders and are never counted as residue.

## Residual human review

Automated checks cannot adjudicate meaning. Items requiring human judgement are listed in
`redaction-report.json` under `manual_review`, and the artifact is not marked
`safe_to_publish: true` unless they are empty.