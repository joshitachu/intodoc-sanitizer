# intodoc-sanitizer

How the intodoc scanner turns a raw integration codebase into a JSON scan
result that is safe to hand to an LLM: **credential redaction** (three layers
plus a fail-closed verification gate) and **noise distillation** (stripping the
UI/boilerplate junk that dominates a Talend export).

This is an extract of the real modules, not a rewrite. Every file under
`src/intodoc/` is the production file, kept at its original import path so the
original test suites run unmodified. Only the surrounding project (CLI,
parsers, platform plugins, prompts, RAG pipeline) has been left out.

Three deliberate deviations from the production files, and nothing else:

- `platforms/talend/__init__.py` is reduced to a docstring, so the distiller
  imports without the full platform plugin (file-classification rules, parser,
  prompts).
- Client-derived identifiers that appeared in comments and test fixtures were
  anonymized before this repo left our network: a client schema table became
  `STG.PHARMACY_VP_CREDENTIALS`, a client job file became `order_load_0.1.item`.
  Both are illustrative strings in prose and test inputs; the properties being
  tested are unchanged.
- `pyproject.toml` is trimmed to the four runtime dependencies these modules
  actually use.

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python demo.py        # end-to-end walkthrough, synthetic data
.venv/bin/python -m pytest -q   # the original test suites
```

---

## The problem

A Talend `.item` is XML holding three things mixed together:

1. **Facts worth documenting** - queries, mappings, endpoints, job wiring.
2. **Secrets** - passwords, tokens, connection strings, internal hostnames.
3. **Noise** - `posX`, `posY`, `offsetLabelX`, `HINT`, encoding defaults,
   repository GUIDs. On a real estate this is the *majority* of the bytes.

(2) must never reach a model. (3) must not be paid for, and actively hurts
answer quality by burying (1). So there are two independent pipelines.

---

## Part 1 - credential redaction

Four stages. The design rule is that **each stage assumes the previous one
missed something.**

### Layer 1 - text, before the parser

`src/intodoc/scanner/credential_filter.py` - `CredentialFilter.filter_text()`

Regex over the raw file text, *before* XML parsing, so a secret cannot reach a
parsed model in the first place. Roughly 40 pattern families: Talend `enc:` and
`id_Password` values, JDBC/generic connection strings, query-string credential
params, `RAW()` wrappers, X509/private-key blocks, JWTs, GitHub/GitLab/NPM/PyPI
tokens, AWS/GCP/Azure/Databricks keys, `sk-` LLM keys, Slack/Stripe/SendGrid/
Twilio/Mailgun/HubSpot keys, emails, IPs, FQDNs, UNC hosts, and full URIs.

Three levels - `standard` / `strict` / `paranoid` (`config.py::RedactionLevel`)
- control how much beyond secrets gets masked (file paths, database and schema
names, then *every* context value). Projects can extend the ruleset with
`.intodoc-redact.yaml` (extra patterns, safe domains, sensitive variable names).

Things worth knowing, each of which came from a real failure:

- **xmlns declarations are masked out and restored verbatim.** Namespace URIs
  are document structure; redacting them breaks `xsi:type` resolution in every
  downstream parser.
- **A credential *path* must be proven to be a file path.** An earlier version
  matched `credential` as a bare substring, so `row2.key`, `this.key` and a
  business table named `..._CREDENTIALS` all became `[CREDENTIAL_PATH]`, taking
  the SQL that referenced them along. Now it needs a path separator, or a
  credential-named stem *plus* a known file extension (`.pem` stands alone).
- **The anchors are load-bearing for performance, not style.** Without the
  leading `(?<![^\s"'<>])`, the unbounded runs retry at every position in every
  token - one 16 KB file cost 1.08 s for zero matches, and one job file 60.3 s.
- **`key` is only sensitive when qualified.** `AES_Key`, `API_Key`,
  `AuthenticationKey` yes; `PrimaryKey`, `KeyColumn`, `BusinessKey` no.

**Mask-and-CAPTURE, not mask-and-discard.** `describe_value()` runs on a value
*before* it is redacted and returns a `RedactionDescriptor` holding only
provably-safe structural facts: scheme (from a closed vocabulary), category
(`db`/`rest`/`jms`/`file`/...), `auth_present`, auth *type*, TLS on/off,
`host_present`. Never a host, path, query string, username or credential. So
documentation can still say *"an authenticated HTTPS REST endpoint with an API
key"* instead of just `[URL_REDACTED]`. Anything not provable is left `None` -
guessing is not allowed.

### Layer 2 - structure, after the parser

`src/intodoc/scanner/post_filter.py`

Walks the parsed Pydantic models and redacts by **what a field means**, not by
what it looks like. Pattern matching cannot catch `<contextParameter
name="MaximoPassword" value="pl41nt3xt"/>` - the value is an ordinary-looking
string; the *name* is the evidence.

`is_sensitive_var_name()` tokenizes a name on separators **and camelCase
boundaries**, so `MaximoPassword`, `maximo_password` and `AES_Key` are all
recognized. Suffix-only matching missed camelCase entirely and let cleartext
secrets through.

This layer also handles the cases one level down that the layer above cannot
see - e.g. a `tRunJob` `CONTEXTPARAMS` TABLE row, where the parameter is called
`CONTEXTPARAMS` and the sensitivity is stated by the row's own NAME cell.
`ComponentParam.row_column_key()` is defined once on the model precisely so the
parser, this filter and the verification gate cannot disagree about which cell
names which - a second copy of that rule is how a value slips past one of them.

### Layer 3 - verification gate

`src/intodoc/scanner/redaction_verifier.py`

Independent check *before anything is written to disk*. It re-runs the filter's
own detectors over every string leaf of `model_dump()`, plus name/type-driven
checks on the structured fields. Anything it flags, by construction, escaped
both filters. On failure the scan writes **no output at all** (overridable with
`allow_redaction_failures`).

Two properties that matter:

- **The report never contains a raw value** - only categories, locations and
  SHA-256 prefixes. Same for the audit trail (`get_audit_report()`).
- **The leaf sweep walks `model_dump()`**, so every collection added to
  `ScanResult` later is covered without being named here. Which is exactly why
  new artifacts must be fields of `ScanResult` and not written from somewhere
  the gate cannot see.

A placeholder is not a residual: counting `value="[PASSWORD_REDACTED]"` as a
finding made every correctly-redacted file look like a leak.

### Layer 4 - sanitized source mirror (not included here)

For the enterprise lane the scanner also publishes a redacted mirror of every
textual source file. It applies `redact_named_value_pairs()` and then **refuses
any file that still trips `detect_residual()`** - categories logged, never
values. That writer (`scanner/evidence_store.py`) is omitted from this extract,
but both methods it depends on are in `credential_filter.py`.

---

## Part 2 - noise distillation

`src/intodoc/platforms/base_distiller.py` (generic) and
`src/intodoc/platforms/talend/distiller.py` (Talend rules)

Runs after redaction, before chunking. Six passes:

| Pass | What it drops |
|---|---|
| Name/prefix/substring strip | `posX`, `posY`, `sizeX`, `offsetLabel*`, `HINT`, `HELP`, `COMMENT`, `PREVIEW`, repository GUIDs, `TSTATCATCHER_STATS`, separator/encoding defaults |
| Empty + default values | empty strings, and values in `STRIP_VALUES` (`false`, `0`, `auto`, `utf-8`, ...) |
| Field-type allowlists | `CHECK` and `CLOSED_LIST` params are dropped unless explicitly kept - a boolean that is the same everywhere carries no information |
| Project-wide constants | a param with exactly one distinct value across the whole project (on 3+ components) tells the model nothing and is removed globally |
| Chunk-level defaults | where >90% of components share a value, the value becomes a chunk default and only the *exceptions* stay on components |
| Context compaction | a variable whose value is identical in every environment collapses to one representative; inline job contexts duplicating chunk-level ones are deduped |

Structural components (`tPrejob`, `tPostjob`, `tUnite`, `tFlowToIterate`) are
kept even when every parameter is stripped - their presence *is* the fact.

Then jobs are grouped and bin-packed into ~30K-token chunks (split at 40K), each
with only the connections, contexts, routines and manifest edges that its own
jobs reference. The distiller prints a before/after token reduction report.

Ordering rule: **distill after redaction, never before.** The distiller's
allowlists would otherwise drop the very params the filter needs to inspect.

---

## Layout

```
src/intodoc/
  config.py                          RedactionLevel + settings
  models.py                          scan data model
  scanner/
    credential_filter.py             Layer 1 + all detectors
    post_filter.py                   Layer 2, structural
    redaction_verifier.py            Layer 3, fail-closed gate
  platforms/
    base_distiller.py                generic distill + chunking
    talend/distiller.py              Talend noise rules
tests/                               original suites, 193 tests
demo.py                              runnable walkthrough (synthetic data)
```

---

## Reading order

1. `demo.py` - see it work, end to end.
2. `credential_filter.py` - the pattern set and `describe_value`. The comments
   are the useful part: nearly every one records a specific verified failure.
3. `post_filter.py` - why patterns alone are not enough.
4. `redaction_verifier.py` - the fail-closed gate.
5. `talend/distiller.py` - the noise rules.

---

*Internal - Intodata. Contains no client source, no client data and no real
credentials; every secret in the demo and the tests is fabricated.*
