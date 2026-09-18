"""Post-scan redaction verification gate.

Defense in depth: after both redaction layers (text-level CredentialFilter,
structural post_filter) have run, independently verify the ScanResult holds
no residual secrets BEFORE any output is written. A single missed regex must
never flow silently into published artifacts again.

The report NEVER contains raw values -- only names, locations, categories
and SHA-256 hash prefixes.
"""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel

from intodoc.models import ComponentParam, Landscape, LineageMatrix, ScanResult
from intodoc.scanner.credential_filter import CredentialFilter


class RedactionVerificationError(RuntimeError):
    """Raised when the scan output still contains suspected secrets."""


def _hash_prefix(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def _is_placeholder(value: str) -> bool:
    """True for redaction placeholders like [PASSWORD_REDACTED], [HOSTNAME]."""
    v = value.strip()
    return v.startswith("[") and v.endswith("]")


def _finding(category: str, location: str, name: str, value: str) -> dict[str, str]:
    return {
        "category": category,
        "location": location,
        "name": name,
        "value_sha256": _hash_prefix(value),
    }


def _check_named_value(
    findings: list[dict[str, str]],
    cred_filter: CredentialFilter,
    location: str,
    name: str,
    value: str,
    var_type: str = "",
) -> None:
    """Flag a name/value pair whose NAME marks it sensitive but whose value survived."""
    if not value or _is_placeholder(value):
        return
    if var_type and var_type.lower() in ("id_password", "password"):
        findings.append(_finding("unredacted_password_type", location, name, value))
    elif cred_filter.is_sensitive_var_name(name):
        findings.append(_finding("unredacted_sensitive_name", location, name, value))


def _check_table_row(
    findings: list[dict[str, str]],
    cred_filter: CredentialFilter,
    location: str,
    row: dict[str, str],
) -> int:
    """Check a TABLE row's cells against the name its NAME cell states.

    Returns the number of values checked. Uses the same
    `ComponentParam.row_column_key` rule as the parser and the structural
    filter, so all three agree on which cell names which.
    """
    name_key = ComponentParam.row_column_key(row, "NAME")
    name = row.get(name_key, "")
    if not name:
        return 0
    checked = 0
    for key, value in row.items():
        if key == name_key:
            continue
        checked += 1
        _check_named_value(findings, cred_filter, f"{location}/{key}", name, value)
    return checked


# Structural identifier fields: filesystem/schema locations the scanner
# assigns itself (never passed through the filter, since a file's own path
# is not sensitive content). Matched by exact key, not substring, so an
# unrelated field like `critical_path` (a dependency-chain list) is not
# swept up by accident. Excluded from the leaf sweep because they can
# innocently contain a credential-pattern substring -- e.g. a Talend job or
# file legitimately named `LoadCredentialsTable` -- without carrying any
# actual secret; the filter passes correctly never touch these fields, so
# the verifier must not either or it flags a false positive on every scan
# that happens to contain such a name.
#
# The second group is the same rule for identifiers the SCANNER composes:
# `mapping_accounting` and `lineage` build `f"{table}.{column}"` out of two
# separately-parsed names, so that spelling is not text any filter pass ever
# saw, and re-running text detectors over it judges a token the source file
# does not contain. Verified: a mapper offering a column named `key` on input
# table `row2` produced `row2.key`, which the credential-path pattern read as
# a key-file path and failed the whole scan on -- and the same construction
# would read a column named `nl` on table `customer` as an FQDN. Both halves
# of every such pair are already swept on their own, as `ContextVariable.name`
# / `SchemaColumn.name` leaves, so nothing is excused from checking here.
_STRUCTURAL_LEAF_KEYS = frozenset({
    "path", "relative_path", "file_path", "unique_name", "xpath",
    "source_refs", "dynamic_refs", "unwritten_offered",
})


def _walk_strings(node: Any, path: str, out: list[tuple[str, str]]) -> None:
    """Collect (path, string) leaves from a model_dump tree.

    Skips `_STRUCTURAL_LEAF_KEYS` entirely -- see module comment above.
    """
    if isinstance(node, str):
        out.append((path, node))
    elif isinstance(node, dict):
        for k, v in node.items():
            if k in _STRUCTURAL_LEAF_KEYS:
                continue
            _walk_strings(v, f"{path}/{k}", out)
    elif isinstance(node, (list, tuple)):
        for i, v in enumerate(node):
            _walk_strings(v, f"{path}/{i}", out)


def verify_model_leaves(
    model: BaseModel,
    cred_filter: CredentialFilter,
) -> dict[str, Any]:
    """Leaf-string sweep over any Pydantic model's JSON dump.

    Model-agnostic layer-3 check: walks every string leaf and re-runs the
    filter's own detectors. Anything flagged now, by construction, escaped
    the earlier filtering stages. Used for `ScanResult` (with the
    additional name/type-driven checks in `verify_scan_result`) and for
    other scan-derived artifacts, such as `LineageMatrix`, that must pass
    through the same defense-in-depth gate before being written to disk.

    Returns a dict with `checked_string_leaves`, `residual_pattern_counts`,
    and `residual_locations`. Raw values never appear in the result.
    """
    leaves: list[tuple[str, str]] = []
    _walk_strings(model.model_dump(mode="json"), "", leaves)
    residual: dict[str, int] = {}
    residual_locations: list[str] = []
    for path, text in leaves:
        if len(text) < 8 or _is_placeholder(text):
            continue
        detected = cred_filter.detect(text)
        if detected:
            for cat, count in detected.items():
                residual[cat] = residual.get(cat, 0) + count
            if len(residual_locations) < 50:
                residual_locations.append(path)

    return {
        "checked_string_leaves": len(leaves),
        "residual_pattern_counts": residual,
        "residual_locations": residual_locations,
    }


def verify_scan_result(
    result: ScanResult,
    cred_filter: CredentialFilter,
) -> dict[str, Any]:
    """Verify a filtered ScanResult carries no residual secrets.

    Checks:
    1. No context variable / component param / TABLE row cell / schema
       column default whose NAME is sensitive (per the token-aware matcher)
       still carries a non-placeholder value.
    2. No id_Password-typed value survives unredacted.
    3. Leaf-string sweep with the same detectors the filter uses: anything
       detected now, by construction, escaped the filter. The sweep walks
       `model_dump`, so every additive collection on `ScanResult`
       (structures, xslt_transforms, services, mapping_accounting,
       capability_ledger) is covered without being named here -- which is
       exactly why they must stay fields of `ScanResult` and not be written
       to disk from somewhere the gate cannot see.

    Returns a report dict with `passed`, `findings`, and
    `residual_pattern_counts`. Raw values never appear in the report.
    """
    findings: list[dict[str, str]] = []
    checked_values = 0

    # 1+2: name/type-driven checks on structured fields
    for cg in result.context_groups:
        for var in cg.variables:
            for env, val in var.values.items():
                checked_values += 1
                _check_named_value(
                    findings, cred_filter,
                    f"context_groups/{cg.name}/{var.name}/{env}",
                    var.name, val, var.type,
                )

    for job in result.jobs:
        for cg in job.context_groups:
            for var in cg.variables:
                for env, val in var.values.items():
                    checked_values += 1
                    _check_named_value(
                        findings, cred_filter,
                        f"jobs/{job.name}/context/{cg.name}/{var.name}/{env}",
                        var.name, val, var.type,
                    )
        for comp in job.components:
            for p in comp.params:
                checked_values += 1
                _check_named_value(
                    findings, cred_filter,
                    f"jobs/{job.name}/components/{comp.unique_name}/{p.name}",
                    p.name, p.value,
                )
                # A TABLE row states its own sensitivity in its NAME cell
                # (tRunJob CONTEXTPARAMS: {PARAM_NAME_COLUMN: "DbPassword",
                # PARAM_VALUE_COLUMN: ...}), which the parameter-name check
                # above cannot see -- the parameter is called CONTEXTPARAMS.
                for index, row in enumerate(p.rows):
                    checked_values += _check_table_row(
                        findings, cred_filter,
                        f"jobs/{job.name}/components/{comp.unique_name}"
                        f"/{p.name}/rows/{index}",
                        row,
                    )
            for schema in comp.schemas:
                for column in schema.columns:
                    checked_values += 1
                    _check_named_value(
                        findings, cred_filter,
                        f"jobs/{job.name}/components/{comp.unique_name}"
                        f"/schemas/{schema.connector}/{column.name}",
                        column.name, column.default_value, column.type,
                    )
        for ref in job.trunjob_refs:
            for p in ref.context_params:
                checked_values += 1
                _check_named_value(
                    findings, cred_filter,
                    f"jobs/{job.name}/trunjob/{ref.child_job}/{p.name}",
                    p.name, p.value,
                )
        for artifact_ref in job.artifact_refs:
            for p in artifact_ref.context_params:
                checked_values += 1
                _check_named_value(
                    findings, cred_filter,
                    f"jobs/{job.name}/artifact_ref/{artifact_ref.target_name}/{p.name}",
                    p.name, p.value,
                )

    for conn in result.metadata_connections:
        for key, val in conn.additional_params.items():
            if isinstance(val, str):
                checked_values += 1
                _check_named_value(
                    findings, cred_filter,
                    f"metadata_connections/{conn.name}/{key}",
                    key, val,
                )

    # 3: leaf-string sweep with the filter's own detectors.
    leaf_report = verify_model_leaves(result, cred_filter)
    residual = leaf_report["residual_pattern_counts"]

    passed = not findings and not residual
    return {
        "passed": passed,
        "checked_values": checked_values,
        "checked_string_leaves": leaf_report["checked_string_leaves"],
        "findings": findings,
        "residual_pattern_counts": residual,
        "residual_locations": leaf_report["residual_locations"],
    }


def verify_lineage_matrix(
    lineage: LineageMatrix,
    cred_filter: CredentialFilter,
) -> dict[str, Any]:
    """Verify a `LineageMatrix` (scan/lineage.json) carries no residual secrets.

    `intodoc.lineage` re-runs `CredentialFilter.filter_text` on every
    expression it copies out of already-filtered tMap data (defense in
    depth), but the lineage document is a new artifact assembled from
    scratch and must pass through the same layer-3 gate as `scan_result.json`
    before it is written -- expressions can embed secrets (verified: tMap
    expressions carry inline string literals, e.g. credential-handling
    business text). Raw values never appear in the report.
    """
    leaf_report = verify_model_leaves(lineage, cred_filter)
    residual = leaf_report["residual_pattern_counts"]
    return {
        "passed": not residual,
        "checked_string_leaves": leaf_report["checked_string_leaves"],
        "findings": [],
        "residual_pattern_counts": residual,
        "residual_locations": leaf_report["residual_locations"],
    }


def verify_landscape(
    landscape: Landscape,
    cred_filter: CredentialFilter,
) -> dict[str, Any]:
    """Verify a `Landscape` (scan/landscape.json) carries no residual secrets.

    Same layer-3 gate as `verify_lineage_matrix`: `intodoc.landscape` only
    ever copies through names/kinds/context-group labels (never a raw
    host/URL/credential -- see module docstring), but the landscape
    document is a new assembled artifact and must independently pass the
    same leaf-string sweep before being written. Raw values never appear
    in the report.
    """
    leaf_report = verify_model_leaves(landscape, cred_filter)
    residual = leaf_report["residual_pattern_counts"]
    return {
        "passed": not residual,
        "checked_string_leaves": leaf_report["checked_string_leaves"],
        "findings": [],
        "residual_pattern_counts": residual,
        "residual_locations": leaf_report["residual_locations"],
    }
