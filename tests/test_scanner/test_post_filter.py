"""Tests for post-parse structural filter."""

from pathlib import Path

from intodoc.config import RedactionLevel
from intodoc.models import (
    ComponentParam,
    Component,
    ContextGroup,
    ContextVariable,
    FileType,
    MetadataConnection,
    ParsedJob,
    ScanResult,
    ScannedFile,
    TMapData,
    TMapEntry,
)
from intodoc.scanner.credential_filter import CredentialFilter
from intodoc.scanner.post_filter import filter_scan_result


def _make_scan_result(**kwargs) -> ScanResult:
    """Helper to create a minimal ScanResult for testing."""
    defaults = {
        "platform": "talend",
        "repo_root": "/test",
    }
    defaults.update(kwargs)
    return ScanResult(**defaults)


def test_post_filter_normalizes_internal_uri_tokens_in_unstructured_mapper_fields():
    """Descriptor markers may occur in XML mapper text without a matching
    ComponentParam descriptor slot; they must never reach scan_result.json."""
    cf = CredentialFilter()
    marker = cf.filter_text(
        "https://api.example.com/orders?token=FakeMapperSecret42",
        capture_uri_descriptors=True,
    )
    result = _make_scan_result(jobs=[ParsedJob(
        name="MapJob", path="process/MapJob",
        tmap_data=[TMapData(entries=[TMapEntry(
            table_name="out", column_name="value", expression=f'"{marker}"',
        )])],
    )])

    filter_scan_result(result, cf)

    assert marker not in result.model_dump_json()
    assert "[URL_REDACTED]" in result.jobs[0].tmap_data[0].entries[0].expression


# ── MetadataConnection redaction ────────────────────────────────────


def test_connection_host_always_redacted():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(metadata_connections=[
        MetadataConnection(
            xmi_id="c1", name="MSSQL_prod", connection_type="MSSQL",
            host="079talend02.keune.com", port="1433", database="BioDB",
        ),
    ])
    filter_scan_result(result, cf)

    conn = result.metadata_connections[0]
    assert conn.host == "[HOST_REDACTED]"
    # Database preserved at standard level
    assert conn.database == "BioDB"


def test_connection_database_redacted_strict():
    cf = CredentialFilter(level=RedactionLevel.STRICT)
    result = _make_scan_result(metadata_connections=[
        MetadataConnection(
            xmi_id="c1", name="BQ_prod", connection_type="BigQuery",
            host="bigquery.googleapis.com", database="vaxxinova-dwh",
            schema_name="staging",
        ),
    ])
    filter_scan_result(result, cf)

    conn = result.metadata_connections[0]
    assert conn.host == "[HOST_REDACTED]"
    assert conn.database == "[DATABASE_REDACTED]"
    assert conn.schema_name == "[SCHEMA_REDACTED]"


def test_connection_file_path_redacted():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(metadata_connections=[
        MetadataConnection(
            xmi_id="c1", name="FileConn", connection_type="File",
            file_path="/data/exports/vaxxinova.csv",
        ),
    ])
    filter_scan_result(result, cf)

    conn = result.metadata_connections[0]
    assert conn.file_path == "[FILE_PATH_REDACTED]"


def test_connection_name_preserved():
    """Connection name (e.g., 'MSSQL_prod') is structural, not sensitive."""
    cf = CredentialFilter(level=RedactionLevel.STRICT)
    result = _make_scan_result(metadata_connections=[
        MetadataConnection(xmi_id="c1", name="MSSQL_prod", connection_type="MSSQL"),
    ])
    filter_scan_result(result, cf)

    assert result.metadata_connections[0].name == "MSSQL_prod"


def test_connection_type_preserved():
    """Connection type (MSSQL, BigQuery, etc.) is structural."""
    cf = CredentialFilter(level=RedactionLevel.STRICT)
    result = _make_scan_result(metadata_connections=[
        MetadataConnection(xmi_id="c1", name="x", connection_type="BigQuery"),
    ])
    filter_scan_result(result, cf)

    assert result.metadata_connections[0].connection_type == "BigQuery"


# ── Context variable redaction ──────────────────────────────────────


def test_password_type_variable_redacted():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(context_groups=[
        ContextGroup(name="Default", variables=[
            ContextVariable(
                name="db_pass", type="id_Password",
                values={"Default": "super_secret_123"},
            ),
        ]),
    ])
    filter_scan_result(result, cf)

    var = result.context_groups[0].variables[0]
    assert var.values["Default"] == "[PASSWORD_REDACTED]"


def test_sensitive_name_variable_redacted():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(context_groups=[
        ContextGroup(name="Default", variables=[
            ContextVariable(
                name="api_token", type="String",
                values={"Default": "tok_abc123"},
            ),
        ]),
    ])
    filter_scan_result(result, cf)

    var = result.context_groups[0].variables[0]
    assert var.values["Default"] == "[REDACTED]"


def test_infra_var_redacted_strict():
    cf = CredentialFilter(level=RedactionLevel.STRICT)
    result = _make_scan_result(context_groups=[
        ContextGroup(name="Default", variables=[
            ContextVariable(
                name="activemq_user", type="String",
                values={"Default": "admin"},
            ),
        ]),
    ])
    filter_scan_result(result, cf)

    var = result.context_groups[0].variables[0]
    assert var.values["Default"] == "[REDACTED]"


def test_infra_var_preserved_standard():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(context_groups=[
        ContextGroup(name="Default", variables=[
            ContextVariable(
                name="activemq_user", type="String",
                values={"Default": "admin"},
            ),
        ]),
    ])
    filter_scan_result(result, cf)

    # Standard level does NOT redact infra vars like _user
    var = result.context_groups[0].variables[0]
    assert var.values["Default"] == "admin"


def test_paranoid_redacts_all_values():
    cf = CredentialFilter(level=RedactionLevel.PARANOID)
    result = _make_scan_result(context_groups=[
        ContextGroup(name="Default", variables=[
            ContextVariable(
                name="batch_size", type="int",
                values={"Default": "1000"},
            ),
            ContextVariable(
                name="output_format", type="String",
                values={"Default": "csv"},
            ),
        ]),
    ])
    filter_scan_result(result, cf)

    for var in result.context_groups[0].variables:
        assert var.values["Default"] == "[REDACTED]"


def test_normal_var_text_filtered():
    """Non-sensitive variables still get text-level pattern matching."""
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(context_groups=[
        ContextGroup(name="Default", variables=[
            ContextVariable(
                name="some_config", type="String",
                values={"Default": "http://server.example.com/api"},
            ),
        ]),
    ])
    filter_scan_result(result, cf)

    var = result.context_groups[0].variables[0]
    assert "example.com" not in var.values["Default"]


# ── Job component param filtering ──────────────────────────────────


def test_job_component_params_filtered():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(
                    unique_name="tRest_1", component_type="tRESTClient",
                    params=[
                        ComponentParam(
                            name="URL",
                            value="http://internal.server.com:8080/api",
                            field_type="TEXT",
                        ),
                    ],
                ),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    param = result.jobs[0].components[0].params[0]
    assert "internal.server.com" not in param.value


def test_component_type_preserved():
    """Component type names must never be redacted."""
    cf = CredentialFilter(level=RedactionLevel.STRICT)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(unique_name="tMSSql_1", component_type="tMSSqlInput"),
                Component(unique_name="tBQ_1", component_type="tBigQueryOutput"),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    assert result.jobs[0].components[0].component_type == "tMSSqlInput"
    assert result.jobs[0].components[1].component_type == "tBigQueryOutput"


# ── Job-level context groups ────────────────────────────────────────


def test_job_context_groups_filtered():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            context_groups=[
                ContextGroup(name="Default", variables=[
                    ContextVariable(
                        name="db_password", type="id_Password",
                        values={"Default": "secret123"},
                    ),
                ]),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    var = result.jobs[0].context_groups[0].variables[0]
    assert var.values["Default"] == "[PASSWORD_REDACTED]"


# ── Audit integration ──────────────────────────────────────────────


def test_post_filter_audit_recorded():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(
        metadata_connections=[
            MetadataConnection(
                xmi_id="c1", name="x", connection_type="MSSQL",
                host="prod-server.internal",
            ),
        ],
        context_groups=[
            ContextGroup(name="Default", variables=[
                ContextVariable(
                    name="api_secret", type="String",
                    values={"Default": "s3cret"},
                ),
            ]),
        ],
    )
    filter_scan_result(result, cf)

    report = cf.get_audit_report()
    assert report["total_redactions"] > 0


# ── ComponentParam name-based redaction ────────────────────────────


def test_component_param_sensitive_name_redacted():
    """Param named 'api_key' must be redacted unconditionally regardless of value format."""
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(
                    unique_name="tRest_1", component_type="tRESTClient",
                    params=[
                        ComponentParam(name="api_key", value="prod-internal-custom-xyz123", field_type="TEXT"),
                    ],
                ),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    param = result.jobs[0].components[0].params[0]
    assert param.value == "[REDACTED]"


def test_component_param_auth_token_name_redacted():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(
                    unique_name="tRest_1", component_type="tRESTClient",
                    params=[
                        ComponentParam(name="auth_token", value="some-internal-token-value", field_type="TEXT"),
                    ],
                ),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    param = result.jobs[0].components[0].params[0]
    assert param.value == "[REDACTED]"


def test_component_param_bearer_value_redacted_by_pattern():
    """Param with generic name but Bearer token value must be caught by text filter."""
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(
                    unique_name="tRest_1", component_type="tRESTClient",
                    params=[
                        ComponentParam(name="HEADER_VALUE_1", value="Bearer xyz123abcdefghijklmno", field_type="TEXT"),
                    ],
                ),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    param = result.jobs[0].components[0].params[0]
    assert "xyz123abcdefghijklmno" not in param.value
    assert "[BEARER_TOKEN_REDACTED]" in param.value


# ── Redaction descriptors ("mask-and-CAPTURE") ─────────────────────
#
# post_filter must keep redacting exactly as before (placeholder text
# unchanged) while ADDITIONALLY attaching a RedactionDescriptor capturing
# safe structural facts about the original value. These tests prove both:
# (a) the descriptor is populated with the right facts, and (b) no secret
# substring ever survives into the descriptor.


def test_component_param_url_redaction_attaches_descriptor():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(
                    unique_name="tRest_1", component_type="tRESTClient",
                    params=[
                        ComponentParam(
                            name="URL",
                            value="https://svc:S3cr3tPass@internal.server.com:8443/api",
                            field_type="TEXT",
                        ),
                    ],
                ),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    param = result.jobs[0].components[0].params[0]
    # Existing redaction behavior is unchanged (the generic user:pass@
    # connection-string pattern fires before URL redaction for this shape)
    assert "internal.server.com" not in param.value
    assert "S3cr3tPass" not in param.value
    assert "[CONNECTION_STRING_REDACTED]" in param.value
    # New: descriptor captures safe structural facts
    d = param.redaction_descriptor
    assert d is not None
    assert d.scheme == "https"
    assert d.tls is True
    assert d.auth_present is True
    assert d.auth_type == "basic"
    assert d.host_present is True
    dumped = d.model_dump_json()
    assert "S3cr3tPass" not in dumped
    assert "internal.server.com" not in dumped


def test_component_param_sensitive_name_redaction_attaches_descriptor():
    """Params redacted purely by sensitive NAME (e.g. api_key) still get a
    descriptor extracted from the original value where possible."""
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(
                    unique_name="tRest_1", component_type="tRESTClient",
                    params=[
                        ComponentParam(
                            name="api_key",
                            value="jms://broker.internal:61616/queue",
                            field_type="TEXT",
                        ),
                    ],
                ),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    param = result.jobs[0].components[0].params[0]
    assert param.value == "[REDACTED]"
    d = param.redaction_descriptor
    assert d is not None
    assert d.scheme == "jms"
    assert d.category == "jms"
    assert "broker.internal" not in d.model_dump_json()


def test_connection_host_redaction_attaches_descriptor():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(metadata_connections=[
        MetadataConnection(
            xmi_id="c1", name="MSSQL_prod", connection_type="MSSQL",
            host="079talend02.keune.com", port="1433", database="BioDB",
        ),
    ])
    filter_scan_result(result, cf)

    conn = result.metadata_connections[0]
    # Existing redaction behavior is unchanged
    assert conn.host == "[HOST_REDACTED]"
    # New: bare host only yields host_present -- nothing else guessable
    d = conn.host_redaction
    assert d is not None
    assert d.host_present is True
    assert d.scheme is None
    assert "079talend02" not in d.model_dump_json()
    assert "keune.com" not in d.model_dump_json()


def test_context_variable_password_redaction_attaches_descriptor():
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(context_groups=[
        ContextGroup(name="Default", variables=[
            ContextVariable(
                name="db_conn", type="id_Password",
                values={"Default": "jdbc:mysql://dbhost:3306/db?password=Secr3t99"},
            ),
        ]),
    ])
    filter_scan_result(result, cf)

    var = result.context_groups[0].variables[0]
    # Existing redaction behavior is unchanged
    assert var.values["Default"] == "[PASSWORD_REDACTED]"
    d = var.redaction_descriptors["Default"]
    assert d is not None
    assert d.scheme == "jdbc"
    assert d.category == "db"
    assert d.auth_present is True
    assert d.auth_type == "basic"
    assert "Secr3t99" not in d.model_dump_json()
    assert "dbhost" not in d.model_dump_json()


def test_no_descriptor_when_nothing_derivable():
    """A sensitive param with a value that carries no structural signal at
    all (e.g. a bare opaque token) gets redacted but no descriptor -- a
    dropped field beats a fabricated one."""
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(
                    unique_name="tRest_1", component_type="tRESTClient",
                    params=[
                        ComponentParam(name="api_key", value="opaquetoken12345", field_type="TEXT"),
                    ],
                ),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    param = result.jobs[0].components[0].params[0]
    assert param.value == "[REDACTED]"
    assert param.redaction_descriptor is None


def test_recursive_token_normalization_preserves_string_enums():
    """The final marker sweep must not coerce FileType (a str Enum) to str."""
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(files=[
        ScannedFile(
            path=Path("/test/job.item"),
            relative_path="job.item",
            file_type=FileType.JOB,
            sha256="0" * 64,
            size_bytes=1,
        ),
    ])
    original_type = result.files[0].file_type

    filter_scan_result(result, cf)

    assert result.files[0].file_type is original_type
    assert type(result.files[0].file_type) is type(original_type)


def test_component_param_nonsensitive_name_preserved():
    """Params with non-sensitive names and non-credential values must not be redacted."""
    cf = CredentialFilter(level=RedactionLevel.STANDARD)
    result = _make_scan_result(jobs=[
        ParsedJob(
            name="test_job", path="/jobs/test",
            components=[
                Component(
                    unique_name="tRest_1", component_type="tRESTClient",
                    params=[
                        ComponentParam(name="MAX_ROWS", value="1000", field_type="TEXT"),
                        ComponentParam(name="OUTPUT_FORMAT", value="json", field_type="TEXT"),
                    ],
                ),
            ],
        ),
    ])
    filter_scan_result(result, cf)

    params = result.jobs[0].components[0].params
    assert params[0].value == "1000"
    assert params[1].value == "json"
