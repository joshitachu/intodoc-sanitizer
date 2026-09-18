"""Tests for the post-scan redaction verification gate.

All secret values in fixtures are FAKE -- same shape as real leaks, never
real credentials or hostnames.
"""

from intodoc.models import (
    Component,
    ComponentParam,
    ContextGroup,
    ContextVariable,
    FileType,
    ParsedJob,
    ScannedFile,
    ScanResult,
)
from intodoc.scanner.credential_filter import CredentialFilter
from intodoc.scanner.post_filter import filter_scan_result
from intodoc.scanner.redaction_verifier import verify_scan_result


def _scan_result(context_groups=None, jobs=None) -> ScanResult:
    return ScanResult(
        platform="talend",
        repo_root="/fake/repo",
        context_groups=context_groups or [],
        jobs=jobs or [],
    )


def test_clean_scan_passes():
    result = _scan_result(
        context_groups=[
            ContextGroup(name="Ctx", variables=[
                ContextVariable(name="ProcessCode", type="id_String", values={"DEV": "assetcheck"}),
                ContextVariable(name="MaximoPassword", type="id_String", values={"DEV": "[REDACTED]"}),
            ]),
        ],
    )
    report = verify_scan_result(result, CredentialFilter())
    assert report["passed"] is True
    assert report["findings"] == []
    assert report["residual_pattern_counts"] == {}


def test_planted_camelcase_secret_fails():
    """A cleartext value under a camelCase secret name must fail the gate."""
    result = _scan_result(
        context_groups=[
            ContextGroup(name="Ctx", variables=[
                ContextVariable(name="MaximoPassword", type="id_String", values={"DEV": "FAKE+notreal%x=1"}),
            ]),
        ],
    )
    report = verify_scan_result(result, CredentialFilter())
    assert report["passed"] is False
    cats = {f["category"] for f in report["findings"]}
    assert "unredacted_sensitive_name" in cats
    # Raw value must never appear in the report
    assert "FAKE+notreal" not in str(report)


def test_planted_id_password_type_fails():
    result = _scan_result(
        context_groups=[
            ContextGroup(name="Ctx", variables=[
                ContextVariable(name="SomethingElse", type="id_Password", values={"PROD": "FAKEVALUE123"}),
            ]),
        ],
    )
    report = verify_scan_result(result, CredentialFilter())
    assert report["passed"] is False
    cats = {f["category"] for f in report["findings"]}
    assert "unredacted_password_type" in cats


def test_job_level_component_param_secret_fails():
    job = ParsedJob(
        name="Job1",
        path="process/Job1_1.0.item",
        components=[
            Component(
                unique_name="tFake_1",
                component_type="tFake",
                params=[ComponentParam(name="ServiceApiKey", value="FAKE-abc-123", field_type="TEXT")],
            ),
        ],
    )
    report = verify_scan_result(_scan_result(jobs=[job]), CredentialFilter())
    assert report["passed"] is False
    assert any("tFake_1" in f["location"] for f in report["findings"])


def test_residual_pattern_sweep_catches_encrypted_blob():
    """A value that the text layer should have caught fails the sweep."""
    job = ParsedJob(
        name="Job1",
        path="process/Job1_1.0.item",
        components=[
            Component(
                unique_name="tFake_1",
                component_type="tFake",
                params=[ComponentParam(
                    name="HARMLESS_NAME",
                    value="enc:system.encryption.key.v1:FAKEabc123FAKEdef456",
                    field_type="TEXT",
                )],
            ),
        ],
    )
    report = verify_scan_result(_scan_result(jobs=[job]), CredentialFilter())
    assert report["passed"] is False
    assert report["residual_pattern_counts"].get("encrypted_password", 0) >= 1
    assert report["residual_locations"]


def test_full_pipeline_filter_then_verify_passes():
    """After post_filter runs, the planted camelCase secret is redacted and
    the gate passes -- proving filter and verifier share one predicate."""
    result = _scan_result(
        context_groups=[
            ContextGroup(name="Ctx", variables=[
                ContextVariable(name="MaximoPassword", type="id_String", values={"DEV": "FAKE+notreal%x=1"}),
                ContextVariable(name="AES_Key", type="id_String", values={"DEV": "FAKEKEY"}),
            ]),
        ],
        jobs=[ParsedJob(
            name="Job1",
            path="process/Job1_1.0.item",
            components=[Component(
                unique_name="tJavaRow_1",
                component_type="tJavaRow",
                params=[ComponentParam(name="CODE", value='globalMap.put("x", 1);', field_type="MEMO_JAVA")],
            )],
        )],
    )
    cred_filter = CredentialFilter()
    filter_scan_result(result, cred_filter)
    report = verify_scan_result(result, cred_filter)
    assert report["passed"] is True, report
    # And the secrets really are gone
    assert result.context_groups[0].variables[0].values["DEV"] == "[REDACTED]"
    assert result.context_groups[0].variables[1].values["DEV"] == "[REDACTED]"


def test_component_code_field_redacted_by_post_filter():
    """Top-level Component.code must be filtered like any param value."""
    comp = Component(
        unique_name="tJava_1",
        component_type="tJava",
        params=[],
        code='String host = "srvx9999"; // was \\\\srvx9999\\share\\x',
    )
    comp.code = 'copy to \\\\srvx9999\\share\\x'
    job = ParsedJob(name="Job1", path="p/Job1_1.0.item", components=[comp])
    result = _scan_result(jobs=[job])
    filter_scan_result(result, CredentialFilter())
    assert "srvx9999" not in (comp.code or "")


def test_scanned_file_path_naming_credentials_does_not_fail_the_gate():
    """A file living under a 'Credentials' directory is a structural
    identifier, not a leaked secret -- reproduces a real composite-scan
    false positive where `files/N/path` and `files/N/relative_path` tripped
    the `credential_path` pattern on the path string itself. The job's own
    `name`/`path` are deliberately free of the pattern here so only the
    ScannedFile path fields are under test."""
    result = _scan_result(
        jobs=[ParsedJob(name="VaultLoader", path="process/VaultLoader_1.0.item")],
    )
    result.files = [
        ScannedFile(
            path="/repo/TalendRepos/Talend/Credentials/vault.item",
            relative_path="TalendRepos/Talend/Credentials/vault.item",
            file_type=FileType.JOB,
            sha256="0" * 64,
            size_bytes=1,
        ),
    ]
    report = verify_scan_result(result, CredentialFilter())
    assert report["passed"] is True, report
    assert report["residual_pattern_counts"] == {}


def test_unique_name_and_xpath_naming_credentials_does_not_fail_the_gate():
    """Component `unique_name` and TXMLMap `xpath` are also structural
    identifiers, not content -- same false-positive class as ScannedFile paths."""
    job = ParsedJob(
        name="Job1",
        path="process/Job1_1.0.item",
        components=[
            Component(unique_name="tFakeCredentialsLookup_1", component_type="tFake", params=[]),
        ],
    )
    report = verify_scan_result(_scan_result(jobs=[job]), CredentialFilter())
    assert report["passed"] is True, report
    assert report["residual_pattern_counts"] == {}


def test_derive_code_from_params():
    comp = Component(
        unique_name="tJavaFlex_1",
        component_type="tJavaFlex",
        params=[
            ComponentParam(name="CODE_START", value="int i = 0;", field_type="MEMO_JAVA"),
            ComponentParam(name="CODE_MAIN", value="i += 1;", field_type="MEMO_JAVA"),
            ComponentParam(name="CODE_END", value="return i;", field_type="MEMO_JAVA"),
        ],
    )
    assert comp.derive_code_from_params() == "int i = 0;\ni += 1;\nreturn i;"

    empty = Component(unique_name="tMap_1", component_type="tMap", params=[])
    assert empty.derive_code_from_params() is None


def test_scanner_composed_field_references_do_not_fail_the_gate():
    """`mapping_accounting` and `lineage` build `f"{table}.{column}"` out of
    two separately-parsed names, so that spelling is not text any filter pass
    ever saw. Verified failure: a mapper offering a column named `key` on
    input table `row2` produced `row2.key`, the credential-path pattern read
    it as a key-file path, and the scan wrote no output at all. The same
    construction turns a column named `nl` on table `customer` into an FQDN.
    """
    from intodoc.models import MappingAccounting, MappingRow

    result = _scan_result(jobs=[ParsedJob(name="Job1", path="process/Job1_1.0.item")])
    result.mapping_accounting = [
        MappingAccounting(
            unit_id="Job1",
            component_name="tMap_5",
            mapper_kind="tmap",
            unwritten_offered=["row2.key", "customer.nl"],
            rows=[
                MappingRow(
                    output_table="out",
                    output_field="id",
                    classification="direct_map",
                    source_refs=["row2.key", "customer.nl"],
                    dynamic_refs=["context.key"],
                ),
            ],
        ),
    ]
    report = verify_scan_result(result, CredentialFilter())
    assert report["passed"] is True, report
    assert report["residual_pattern_counts"] == {}
