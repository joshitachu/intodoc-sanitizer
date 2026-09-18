"""Tests for credential filter -- both existing patterns and new enhancements."""

from pathlib import Path
from textwrap import dedent


from intodoc.config import RedactionLevel
from intodoc.scanner.credential_filter import CredentialFilter


# ── Existing pattern tests (regression) ─────────────────────────────


def test_encrypted_password_redacted():
    f = CredentialFilter()
    text = 'value="enc:system.encryption.key.v1:DxjMAtbVkm0XorVCWFYLz0QmhoXXPvStdgzqQI1Io2uAUlaRylNsiTNQH41ORrjY"'
    result = f.filter_text(text)
    assert "enc:system.encryption.key.v1" not in result
    assert "[ENCRYPTED_PASSWORD]" in result


def test_ip_address_redacted():
    f = CredentialFilter()
    text = 'ServerName="192.168.1.100"'
    result = f.filter_text(text)
    assert "192.168.1.100" not in result
    assert "[SERVER_IP]" in result


def test_jdbc_url_redacted():
    f = CredentialFilter()
    text = 'url="jdbc:sqlserver://admin:secretpass@myserver.com:1433/mydb"'
    result = f.filter_text(text)
    assert "secretpass" not in result
    assert "[CONNECTION_STRING_REDACTED]" in result


def test_descriptor_capture_preserves_xml_encoded_expression_quotes():
    credential_filter = CredentialFilter()
    raw = (
        'expression="&quot;jdbc:sqlserver://user:secret@example.invalid/db&quot;"'
    )

    filtered = credential_filter.filter_text(
        raw,
        filename="Job.item",
        capture_uri_descriptors=True,
    )
    normalized = credential_filter.normalize_redaction_tokens(filtered)

    assert normalized == 'expression="&quot;[CONNECTION_STRING_REDACTED]&quot;"'
    assert "secret" not in normalized


def test_credential_path_redacted():
    f = CredentialFilter()
    text = 'value="/path/to/gcp.json"'
    result = f.filter_text(text)
    assert "gcp.json" not in result
    assert "[CREDENTIAL_PATH]" in result


def test_certificate_stripped():
    f = CredentialFilter()
    text = 'before-----BEGIN CERTIFICATE-----\nMIIBxTCC\n-----END CERTIFICATE-----after'
    result = f.filter_text(text)
    assert "MIIB" not in result


def test_normal_text_untouched():
    f = CredentialFilter()
    text = '<elementParameter field="TEXT" name="DBNAME" value="Biovet"/>'
    result = f.filter_text(text)
    # DBNAME/Biovet don't match any pattern
    assert "Biovet" in result


def test_has_credentials_detects():
    f = CredentialFilter()
    assert f.has_credentials("enc:system.encryption.key.v1:abc123")
    assert not f.has_credentials("just some normal text here no dots")


# ── New patterns: Email ─────────────────────────────────────────────


def test_email_redacted():
    f = CredentialFilter()
    text = 'value="salesforce.integration@vaxxinova.com"'
    result = f.filter_text(text)
    assert "vaxxinova.com" not in result
    assert "[EMAIL_REDACTED]" in result


def test_email_in_xml():
    f = CredentialFilter()
    text = '<param name="FROM" value="admin@company.org"/>'
    result = f.filter_text(text)
    assert "admin@company.org" not in result


# ── New patterns: URL ───────────────────────────────────────────────


def test_http_url_redacted():
    f = CredentialFilter()
    text = 'value="http://079talend02.keune.com:8161/api/message"'
    result = f.filter_text(text)
    assert "079talend02" not in result
    assert "keune.com" not in result
    assert "[URL_REDACTED]" in result


def test_https_url_redacted():
    f = CredentialFilter()
    text = 'endpoint="https://my-api.example.com/v2/data"'
    result = f.filter_text(text)
    assert "example.com" not in result
    assert "[URL_REDACTED]" in result


def test_amqp_url_redacted():
    f = CredentialFilter()
    text = 'broker="amqp://broker.internal:5672/vhost"'
    result = f.filter_text(text)
    assert "broker.internal" not in result
    assert "[URL_REDACTED]" in result


def test_jms_uri_with_query_password_is_redacted_and_detectable():
    """JMS is a supported URI scheme, not an exception to URL redaction.

    The verifier delegates to the same matcher, so this protects both the
    initial scan filter and its independent residual-secret sweep.
    """
    f = CredentialFilter()
    raw = "jms://broker.internal:61616/orders?password=FakeBrokerSecret42"
    result = f.filter_text(raw)
    assert result == "[URL_REDACTED]"
    assert "FakeBrokerSecret42" not in result
    assert f.detect(raw)["url"] == 1


def test_preparse_uri_descriptor_marker_contains_no_raw_uri():
    f = CredentialFilter()
    raw = "https://api.example.com/orders?api_key=FakeApiSecret42"
    marker = f.filter_text(raw, capture_uri_descriptors=True)
    descriptor = f.descriptor_from_redaction_token(marker)
    assert marker.startswith("[INTODOC_URI_DESCRIPTOR_")
    assert "api.example.com" not in marker
    assert "FakeApiSecret42" not in marker
    assert descriptor is not None
    assert descriptor.model_dump(exclude_none=True) == {
        "scheme": "https", "category": "rest", "auth_present": True,
        "auth_type": "api_key", "tls": True, "host_present": True,
    }
    assert f.normalize_redaction_tokens(marker) == "[URL_REDACTED]"


# ── New patterns: FQDN ──────────────────────────────────────────────


def test_fqdn_redacted():
    f = CredentialFilter()
    text = 'host="079talend02.keune.com"'
    result = f.filter_text(text)
    assert "keune.com" not in result
    assert "[HOSTNAME]" in result


def test_fqdn_with_subdomain():
    f = CredentialFilter()
    text = 'server="db-prod.vaxxinova.internal"'
    result = f.filter_text(text)
    assert "vaxxinova.internal" not in result
    assert "[HOSTNAME]" in result


def test_fqdn_safe_domain_preserved():
    """XML namespace domains like w3.org should NOT be redacted."""
    f = CredentialFilter()
    # w3.org must survive even without a protocol prefix
    text2 = 'schema at www.w3.org standard'
    result = f.filter_text(text2)
    assert "w3.org" in result


def test_fqdn_eclipse_preserved():
    f = CredentialFilter()
    # eclipse.org must survive even without a protocol prefix
    text2 = 'from eclipse.org model'
    result = f.filter_text(text2)
    assert "eclipse.org" in result


# ── New patterns: File paths (strict only) ──────────────────────────


def test_windows_path_redacted_strict():
    f = CredentialFilter(level=RedactionLevel.STRICT)
    text = r'value="C:\talend\data\vaxxinova-dwh-8c18bd136cf5.json"'
    result = f.filter_text(text)
    assert "vaxxinova" not in result
    assert "[FILE_PATH_REDACTED]" in result


def test_windows_path_not_redacted_standard():
    f = CredentialFilter(level=RedactionLevel.STANDARD)
    text = r'value="C:\talend\data\output.csv"'
    result = f.filter_text(text)
    # Standard does NOT redact windows file paths (unless they match credential patterns)
    assert r"C:\talend" in result


def test_unix_path_redacted_strict():
    f = CredentialFilter(level=RedactionLevel.STRICT)
    text = 'path="/home/talend/jobs/etl.sh"'
    result = f.filter_text(text)
    assert "/home/talend" not in result
    assert "[FILE_PATH_REDACTED]" in result


def test_unix_opt_path_redacted_strict():
    f = CredentialFilter(level=RedactionLevel.STRICT)
    text = 'dir="/opt/talend/data"'
    result = f.filter_text(text)
    assert "/opt/talend" not in result


# ── False positive safety ───────────────────────────────────────────


def test_talend_component_names_preserved():
    """Talend component type names like tMSSqlInput must NOT be redacted."""
    f = CredentialFilter()
    components = ["tMSSqlInput", "tBigQueryOutput", "tRESTClient", "tMap", "tLogRow"]
    for comp in components:
        result = f.filter_text(comp)
        assert result == comp, f"{comp} was incorrectly redacted to {result}"


def test_safe_domain_url_preserved():
    """URLs on safe (XML namespace / standard) domains must never be redacted.

    Redacting namespace URIs breaks namespaced attribute lookups (xsi:type,
    xmi:id) in every downstream XML parser.
    """
    f = CredentialFilter()
    text = 'xmlns="http://www.w3.org/2001/XMLSchema"'
    result = f.filter_text(text)
    assert result == text


def test_safe_domain_data_url_with_credentials_is_still_redacted():
    """Safe-domain exemption is only for non-auth structural URLs.

    XML namespace declarations remain protected separately by the XMLNS mask.
    """
    f = CredentialFilter()
    raw = "https://talend.org/api?token=FakeNamespaceSecret42"
    assert f.filter_text(raw) == "[URL_REDACTED]"


def test_xmlns_declarations_preserved_in_xml():
    """xmlns declaration values survive filtering verbatim, even for
    non-safe domains -- they are structural identifiers, not data."""
    f = CredentialFilter()
    text = (
        '<?xml version="1.0"?><talendfile:ProcessType '
        'xmlns:talendfile="platform:/resource/org.talend.model/model/TalendFile.xsd" '
        'xmlns:TalendMapper="http://www.talend.org/mapper" '
        'xmlns:xmi="http://www.omg.org/XMI" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:vw="https://integration.client-internal.nl/ns/v1">'
        '<node componentName="tMap"/></talendfile:ProcessType>'
    )
    result = f.filter_text(text, filename="job.item")
    assert 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' in result
    assert 'xmlns:TalendMapper="http://www.talend.org/mapper"' in result
    assert 'xmlns:xmi="http://www.omg.org/XMI"' in result
    assert 'xmlns:vw="https://integration.client-internal.nl/ns/v1"' in result
    assert "__INTODOC_XMLNS_" not in result


def test_non_xmlns_url_still_redacted_in_xml():
    """Endpoint URLs outside xmlns declarations keep getting redacted."""
    f = CredentialFilter()
    text = (
        '<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        '<elementParameter name="ENDPOINT" value="https://api.client-internal.nl/v2/orders"/>'
        "</root>"
    )
    result = f.filter_text(text, filename="job.item")
    assert 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' in result
    assert "api.client-internal.nl" not in result
    assert "[URL_REDACTED]" in result


def test_filtered_xml_keeps_namespaced_attributes_parseable():
    """After filtering, xsi:type attributes must still resolve under the
    original namespace URI when parsed with ElementTree."""
    import xml.etree.ElementTree as ET

    f = CredentialFilter()
    text = (
        '<?xml version="1.0"?><root '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        '<nodeData xsi:type="TalendMapper:MapperData"/></root>'
    )
    result = f.filter_text(text, filename="job.item")
    root = ET.fromstring(result)
    node = root.find("nodeData")
    xsi_type = node.get("{http://www.w3.org/2001/XMLSchema-instance}type")
    assert xsi_type == "TalendMapper:MapperData"


def test_simple_numbers_not_redacted():
    """Version-like numbers should not trigger IP redaction."""
    f = CredentialFilter()
    text = 'version="7.3"'
    result = f.filter_text(text)
    assert result == text


# ── Redaction levels ────────────────────────────────────────────────


def test_level_standard_is_default():
    f = CredentialFilter()
    assert f.level == RedactionLevel.STANDARD


def test_level_strict():
    f = CredentialFilter(level=RedactionLevel.STRICT)
    assert f.level == RedactionLevel.STRICT


def test_level_paranoid():
    f = CredentialFilter(level=RedactionLevel.PARANOID)
    assert f.level == RedactionLevel.PARANOID


# ── Variable name sensitivity ──────────────────────────────────────


def test_sensitive_var_password():
    f = CredentialFilter()
    assert f.is_sensitive_var_name("activemq_password")
    assert f.is_sensitive_var_name("db_secret")
    assert f.is_sensitive_var_name("api_token")
    assert f.is_sensitive_var_name("id_password")


def test_sensitive_var_infra_strict():
    """Infrastructure vars are sensitive only at strict+."""
    f_standard = CredentialFilter(level=RedactionLevel.STANDARD)
    f_strict = CredentialFilter(level=RedactionLevel.STRICT)

    assert not f_standard.is_sensitive_var_name("activemq_user")
    assert not f_standard.is_sensitive_var_name("db_host")

    assert f_strict.is_sensitive_var_name("activemq_user")
    assert f_strict.is_sensitive_var_name("db_host")
    assert f_strict.is_sensitive_var_name("api_endpoint")
    assert f_strict.is_sensitive_var_name("broker_url")


def test_nonsensitive_var():
    f = CredentialFilter(level=RedactionLevel.STRICT)
    assert not f.is_sensitive_var_name("batch_size")
    assert not f.is_sensitive_var_name("max_retries")
    assert not f.is_sensitive_var_name("output_format")


# ── Audit report ────────────────────────────────────────────────────


def test_audit_report_counts():
    f = CredentialFilter()
    f.filter_text('host="079talend02.keune.com"')
    f.filter_text('email="user@example.com"')

    report = f.get_audit_report()
    assert report["redaction_level"] == "standard"
    assert report["total_redactions"] >= 2
    assert "hostname" in report["summary"] or "email_redacted" in report["summary"]


def test_audit_report_no_raw_values():
    """Audit report must NEVER contain raw sensitive values."""
    f = CredentialFilter()
    f.filter_text('secret_host="very-secret-server.internal"')

    report = f.get_audit_report()
    report_str = str(report)
    assert "very-secret-server" not in report_str


def test_audit_reset():
    f = CredentialFilter()
    f.filter_text('host="server.example.com"')
    assert f.get_audit_report()["total_redactions"] > 0

    f.reset_audit()
    assert f.get_audit_report()["total_redactions"] == 0


# ── Custom config ───────────────────────────────────────────────────


def test_custom_config_patterns(tmp_path: Path):
    config = tmp_path / ".intodoc-redact.yaml"
    config.write_text(dedent("""\
        patterns:
          - regex: "079talend\\\\d+"
            replacement: "[INTERNAL_SERVER]"
            level: standard
    """))

    f = CredentialFilter(config_path=config)
    text = 'server="079talend02"'
    result = f.filter_text(text)
    assert "079talend02" not in result
    assert "[INTERNAL_SERVER]" in result


def test_custom_safe_domains(tmp_path: Path):
    config = tmp_path / ".intodoc-redact.yaml"
    config.write_text(dedent("""\
        safe_domains:
          - salesforce.com
    """))

    f = CredentialFilter(config_path=config)
    # salesforce.com should be preserved
    text = 'domain at login.salesforce.com works'
    result = f.filter_text(text)
    assert "salesforce.com" in result


def test_custom_sensitive_vars(tmp_path: Path):
    config = tmp_path / ".intodoc-redact.yaml"
    config.write_text(dedent("""\
        sensitive_vars:
          - "project_id"
    """))

    f = CredentialFilter(config_path=config)
    assert f.is_sensitive_var_name("gcp_project_id")


def test_invalid_custom_config_ignored(tmp_path: Path):
    """Malformed YAML should not crash the filter."""
    config = tmp_path / ".intodoc-redact.yaml"
    config.write_text("not: [valid: yaml: {{")

    # Should not raise
    f = CredentialFilter(config_path=config)
    result = f.filter_text("normal text")
    assert result == "normal text"


# ── New patterns: HTTP auth schemes ────────────────────────────────


def test_bearer_token_redacted():
    f = CredentialFilter()
    result = f.filter_text("Bearer ghp_abc1234567890abcdef")
    assert "ghp_" not in result
    assert "[BEARER_TOKEN_REDACTED]" in result


def test_authorization_bearer_header_redacted():
    f = CredentialFilter()
    result = f.filter_text("Authorization: Bearer 1fae930abc818def0123")
    assert "1fae930abc818def" not in result
    assert "[AUTH_HEADER_REDACTED]" in result


def test_basic_auth_redacted():
    f = CredentialFilter()
    result = f.filter_text("Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA" not in result
    assert "[BASIC_AUTH_REDACTED]" in result


def test_x_api_key_header_redacted():
    f = CredentialFilter()
    result = f.filter_text("X-API-Key: sk_live_abc123def456ghi")
    assert "sk_live_abc123" not in result
    assert "[API_KEY_REDACTED]" in result


# ── New patterns: JWT ───────────────────────────────────────────────


def test_jwt_redacted():
    f = CredentialFilter()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = f.filter_text(jwt)
    assert "eyJhbGciOiJIUzI1NiJ9" not in result
    assert "[JWT_REDACTED]" in result


# ── New patterns: Source-control tokens ────────────────────────────


def test_github_pat_redacted():
    f = CredentialFilter()
    result = f.filter_text("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456")
    assert "ghp_" not in result
    assert "[GITHUB_TOKEN_REDACTED]" in result


def test_github_other_prefixes_redacted():
    f = CredentialFilter()
    for prefix in ("gho_", "ghs_", "ghr_", "ghu_"):
        result = f.filter_text(f"{prefix}abc1234567890abcdef")
        assert prefix not in result
        assert "[GITHUB_TOKEN_REDACTED]" in result


def test_github_fine_grained_pat_redacted():
    f = CredentialFilter()
    result = f.filter_text("github_pat_abc1234567890abcdefghijklmno")
    assert "github_pat_" not in result
    assert "[GITHUB_TOKEN_REDACTED]" in result


def test_gitlab_token_redacted():
    f = CredentialFilter()
    result = f.filter_text("glpat-abcdefghijklmnopqrstu")
    assert "glpat-" not in result
    assert "[GITLAB_TOKEN_REDACTED]" in result


def test_lobster_filter_bearer_redacted():
    """Bearer token embedded in a Lobster filter expression must be caught."""
    f = CredentialFilter()
    result = f.filter_text('const:"Bearer eyJhbGciOiJIUzI1NiJ9.abc.def"')
    assert "eyJhbGciOiJIUzI1NiJ9" not in result


def test_lobster_base64_value_redacted_for_xml_filename():
    f = CredentialFilter(level=RedactionLevel.STRICT)
    result = f.filter_text(
        "<config><value>aHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20=</value></config>",
        filename="filter.xml",
    )
    assert "aHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20=" not in result
    assert "[BASE64_REDACTED]" in result


def test_lobster_base64_value_not_redacted_for_non_xml_filename():
    f = CredentialFilter(level=RedactionLevel.STRICT)
    value = "prefix <value>aHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20=</value>"
    result = f.filter_text(value, filename="notes.txt")
    assert result == value


# ── New patterns: Cloud credentials ────────────────────────────────


def test_aws_access_key_redacted():
    f = CredentialFilter()
    result = f.filter_text("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in result
    assert "[AWS_ACCESS_KEY_REDACTED]" in result


def test_gcp_api_key_redacted():
    f = CredentialFilter()
    result = f.filter_text("AIzaSyB-9hPi6xyzABCDEFGHIJKLMNOPQRSTUVW")
    assert "AIzaSy" not in result
    assert "[GCP_API_KEY_REDACTED]" in result


def test_databricks_token_redacted():
    f = CredentialFilter()
    result = f.filter_text("dapi1234567890abcdef1234567890abcdef")
    assert "dapi1234567890" not in result
    assert "[DATABRICKS_TOKEN_REDACTED]" in result


# ── New patterns: LLM / SaaS keys ──────────────────────────────────


def test_openai_key_redacted():
    f = CredentialFilter()
    result = f.filter_text("sk-proj-abcdefghij1234567890abcdefghij")
    assert "sk-proj-" not in result
    assert "[LLM_API_KEY_REDACTED]" in result


def test_anthropic_key_redacted():
    f = CredentialFilter()
    result = f.filter_text("sk-ant-api03-abc123def456ghi789jkl012")
    assert "sk-ant-" not in result
    assert "[LLM_API_KEY_REDACTED]" in result


def test_slack_token_redacted():
    f = CredentialFilter()
    result = f.filter_text("xoxb-12345-abcdefghijklmnopq")
    assert "xoxb-" not in result
    assert "[SLACK_TOKEN_REDACTED]" in result


def test_stripe_key_redacted():
    f = CredentialFilter()
    result = f.filter_text("sk_live_abcdefghijklmnopqrstu")
    assert "sk_live_" not in result
    assert "[STRIPE_KEY_REDACTED]" in result


def test_sendgrid_key_redacted():
    f = CredentialFilter()
    result = f.filter_text("SG.abc123def456ghijk.xyz789abc012defghijklmno")
    assert "SG.abc123" not in result
    assert "[SENDGRID_KEY_REDACTED]" in result


# ── XML sensitive_keys extended ────────────────────────────────────


def test_authorization_xml_attribute_redacted():
    """XML attribute name='Authorization' value='...' must be caught by _SENSITIVE_KV."""
    f = CredentialFilter()
    text = '<elementParameter name="authorization" value="Bearer ghp_abc123def456"/>'
    result = f.filter_text(text)
    assert "ghp_abc123" not in result


# ── False positive safety for new patterns ─────────────────────────


def test_short_bearer_not_redacted():
    """'Bearer' followed by fewer than 10 chars should not trigger."""
    f = CredentialFilter()
    result = f.filter_text("Bearer short")
    assert result == "Bearer short"


def test_aws_key_prefix_too_short_not_redacted():
    """AKIA with fewer than 16 chars after prefix should not match."""
    f = CredentialFilter()
    result = f.filter_text("AKIA123SHORT")
    assert "AKIA123SHORT" in result


# ── Token-aware sensitive names (camelCase leak regression) ─────────
# Regression for the verified leak: camelCase context vars (MaximoPassword,
# AES_Key) bypassed the old underscore-suffix matching and reached scan
# output, _facts and published docs in cleartext.


def test_camelcase_password_sensitive_at_standard():
    f = CredentialFilter()
    assert f.is_sensitive_var_name("MaximoPassword")
    assert f.is_sensitive_var_name("maximo_password")
    assert f.is_sensitive_var_name("MyServiceSecret")
    assert f.is_sensitive_var_name("ClientCredentials")


def test_qualified_key_sensitive_at_standard():
    f = CredentialFilter()
    assert f.is_sensitive_var_name("AES_Key")
    assert f.is_sensitive_var_name("API_Key")
    assert f.is_sensitive_var_name("AuthenticationKey")
    assert f.is_sensitive_var_name("EncryptionKey")
    assert f.is_sensitive_var_name("private_key")
    assert f.is_sensitive_var_name("access_key")


def test_unqualified_key_not_sensitive():
    """Plain data-modelling 'key' names must NOT be flagged."""
    f = CredentialFilter(level=RedactionLevel.STRICT)
    assert not f.is_sensitive_var_name("KeyColumn")
    assert not f.is_sensitive_var_name("PrimaryKey")
    assert not f.is_sensitive_var_name("BusinessKey")


def test_benign_camelcase_names_not_sensitive():
    f = CredentialFilter(level=RedactionLevel.STRICT)
    assert not f.is_sensitive_var_name("AuthenticationExpiryHour")
    assert not f.is_sensitive_var_name("ProcessCode")
    assert not f.is_sensitive_var_name("LocationData")
    assert not f.is_sensitive_var_name("GlobalFilename")


def test_camelcase_infra_names_strict_only():
    f_standard = CredentialFilter(level=RedactionLevel.STANDARD)
    f_strict = CredentialFilter(level=RedactionLevel.STRICT)

    assert not f_standard.is_sensitive_var_name("MaximoUser")
    assert not f_standard.is_sensitive_var_name("connection_logDB_Username")

    assert f_strict.is_sensitive_var_name("MaximoUser")
    assert f_strict.is_sensitive_var_name("connection_logDB_Username")


def test_tokenize_name_boundaries():
    assert CredentialFilter.tokenize_name("MaximoPassword") == ["maximo", "password"]
    assert CredentialFilter.tokenize_name("AES_Key") == ["aes", "key"]
    assert CredentialFilter.tokenize_name("connection_logDB_Username") == [
        "connection", "log", "db", "username",
    ]


# ── UNC / bare-hostname redaction ───────────────────────────────────
# Regression: bare intranet hostnames (no dot-TLD) in UNC paths escaped
# the FQDN pattern and reached published docs.


def test_unc_backslash_host_redacted():
    f = CredentialFilter()
    text = r"path=\\fileserv01\Dev_Iface$\Some2Thing\LocationData\file.xml"
    result = f.filter_text(text)
    assert "fileserv01" not in result
    assert r"\\[HOSTNAME]\Dev_Iface$" in result


def test_unc_forwardslash_host_redacted():
    f = CredentialFilter()
    text = 'value="//srvx9999/share/folder/file.txt"'
    result = f.filter_text(text)
    assert "srvx9999" not in result
    assert "//[HOSTNAME]/share" in result


def test_unc_dotted_host_still_fqdn_redacted():
    """Dotted share hosts keep going through the FQDN rule."""
    f = CredentialFilter()
    text = 'value="//fileshares-test.fakecorp.nl/Shares$/Interfaces/x/"'
    result = f.filter_text(text)
    assert "fakecorp.nl" not in result
    assert "[HOSTNAME]" in result


def test_unc_pattern_ignores_urls_and_comments():
    f = CredentialFilter()
    # protocol URLs are handled by the URL rule, not mangled by UNC
    assert "[URL_REDACTED]" in f.filter_text("http://intranet-host.example.com/x/y")
    # Java line comments must not be treated as share paths
    code = "int a = 1; //import java.util.List;"
    assert f.filter_text(code) == code


def test_unc_xmlns_declarations_untouched():
    f = CredentialFilter()
    text = (
        '<root xmlns:vw="//nonstd/ns/path">'
        r'<param value="\\srvx9999\share\x"/></root>'
    )
    result = f.filter_text(text, filename="job.item")
    assert 'xmlns:vw="//nonstd/ns/path"' in result
    assert "srvx9999" not in result


# ── detect() residual sweep ─────────────────────────────────────────


def test_detect_reports_categories_without_mutating():
    f = CredentialFilter()
    text = "enc:system.encryption.key.v1:abc123def456 and 192.168.0.1"
    findings = f.detect(text)
    assert findings.get("encrypted_password") == 1
    assert findings.get("server_ip") == 1
    # detect() must not record audit entries
    assert f.get_audit_report()["total_redactions"] == 0


def test_detect_clean_text_empty():
    f = CredentialFilter()
    assert f.detect("SELECT ProcessID from Processes where x = 1") == {}


# ── describe_value() -- "mask-and-CAPTURE" redaction descriptor ────
#
# describe_value() runs on the ORIGINAL value before it is discarded by
# redaction and must return ONLY provably-non-sensitive structural facts.
# These tests cover the representative cases called out in the design
# (https+basic, jms, jdbc, sftp, plain host, no-auth), and separately prove
# no secret substring ever survives into the returned descriptor.


def test_describe_value_https_basic_auth():
    secret = "S3cr3tPassw0rd!"
    value = f"https://svc:{secret}@api.example.com:443/v1/resource"
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.scheme == "https"
    assert d.category == "rest"
    assert d.tls is True
    assert d.auth_present is True
    assert d.auth_type == "basic"
    assert d.host_present is True
    # No secret substring anywhere in the descriptor
    dumped = d.model_dump_json()
    assert secret not in dumped
    assert "api.example.com" not in dumped
    assert "svc" not in dumped


def test_describe_value_jms_no_auth():
    value = "jms://broker.internal:61616/queue/orders"
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.scheme == "jms"
    assert d.category == "jms"
    assert d.tls is False
    assert d.auth_present is False
    assert d.auth_type == "none"
    assert d.host_present is True
    assert "broker.internal" not in d.model_dump_json()


def test_describe_value_jdbc_with_password_param():
    secret = "Sup3rSecret"
    value = f"jdbc:mysql://dbhost.internal:3306/proddb?user=svc_acct&password={secret}"
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.scheme == "jdbc"
    assert d.category == "db"
    assert d.auth_present is True
    assert d.auth_type == "basic"
    assert d.host_present is True
    dumped = d.model_dump_json()
    assert secret not in dumped
    assert "dbhost.internal" not in dumped
    assert "svc_acct" not in dumped
    assert "proddb" not in dumped


def test_describe_value_jdbc_encrypt_flag_sets_tls():
    value = "jdbc:sqlserver://dbhost;databaseName=Prod;user=svc;password=Secret1;encrypt=true"
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.scheme == "jdbc"
    assert d.tls is True
    assert d.auth_present is True
    assert d.auth_type == "basic"
    assert "Secret1" not in d.model_dump_json()


def test_describe_value_sftp_bare_username():
    value = "sftp://svcuser@sftp.example.com/incoming/orders.csv"
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.scheme == "sftp"
    assert d.category == "file"
    assert d.tls is True
    assert d.auth_present is True
    assert d.auth_type == "unknown"  # bare username, no password visible
    assert d.host_present is True
    dumped = d.model_dump_json()
    assert "svcuser" not in dumped
    assert "sftp.example.com" not in dumped


def test_describe_value_plain_host():
    """A bare hostname (no scheme) only yields host_present -- nothing else
    can be safely determined, so scheme/auth/tls must stay None. Without
    the caller asserting `is_host`, an un-schemed value with no other
    signal is not guessed at all (see test below)."""
    value = "db-prod-01.internal.corp"
    d = CredentialFilter.describe_value(value, is_host=True)
    assert d is not None
    assert d.host_present is True
    assert d.scheme is None
    assert d.category is None
    assert d.auth_present is None
    assert d.auth_type is None
    assert d.tls is None
    assert "db-prod-01" not in d.model_dump_json()


def test_describe_value_without_is_host_hint_does_not_guess():
    """The same bare-hostname-shaped string returns None when the caller
    does NOT assert is_host -- an arbitrary opaque secret can look
    hostname-shaped too, so this must never be inferred from characters
    alone."""
    assert CredentialFilter.describe_value("db-prod-01.internal.corp") is None
    assert CredentialFilter.describe_value("opaquetoken12345") is None


def test_describe_value_explicit_no_auth():
    value = "https://api.example.com/public/health"
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.auth_present is False
    assert d.auth_type == "none"
    assert d.tls is True
    assert "api.example.com" not in d.model_dump_json()


def test_describe_value_bearer_token():
    secret = "xyz123abcdefghijklmno"
    value = f"Bearer {secret}"
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.auth_present is True
    assert d.auth_type == "bearer"
    assert secret not in d.model_dump_json()


def test_describe_value_basic_auth_header():
    value = "Basic dXNlcjpwYXNzd29yZA=="
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.auth_present is True
    assert d.auth_type == "basic"
    assert "dXNlcjpwYXNzd29yZA" not in d.model_dump_json()


def test_describe_value_unknown_scheme_prefix_not_reported():
    """A value with an unrecognized colon-prefixed token (not a real URI
    scheme) must NEVER have that token echoed back as `scheme` -- only
    known protocol tokens are recognized. The legitimate auth signal
    elsewhere in the value is still captured."""
    value = "faketoken1234:xyz?password=Secret123"
    d = CredentialFilter.describe_value(value)
    assert d is not None
    assert d.scheme is None
    assert d.auth_present is True
    assert d.auth_type == "basic"
    dumped = d.model_dump_json()
    assert "faketoken1234" not in dumped
    assert "Secret123" not in dumped


def test_describe_value_empty_and_non_string_returns_none():
    assert CredentialFilter.describe_value("") is None
    assert CredentialFilter.describe_value("   ") is None
    assert CredentialFilter.describe_value(None) is None  # type: ignore[arg-type]


def test_describe_value_plain_text_returns_none():
    """Ordinary non-connection text yields nothing determinable."""
    assert CredentialFilter.describe_value("batch_size=1000") is None
    assert CredentialFilter.describe_value("just some ordinary text value") is None


# --- Redaction must stay linear in token length -----------------------------
#
# The credential-path pattern has two unbounded `[^\s"'<>]*` runs around an
# alternation. Unanchored, it is retried at every position inside every
# delimiter-free token, which is quadratic in token length. Measured on a real
# Talend estate before the token-start anchor was added: a 16 KB metadata file
# cost 1.08s for zero matches and `order_load_0.1.item` cost 60.3s, so a
# sanitized-workspace pass over 6,768 files spent 89.6s in this one pattern.
# These tests pin the complexity, because the symptom is a scan that looks
# hung rather than a scan that fails.

def test_long_delimiter_free_token_does_not_blow_up_redaction():
    import time

    from intodoc.scanner.credential_filter import CredentialFilter

    # One 40,000-character token with no whitespace, quotes or angle brackets
    # and no credential marker: the worst case, because nothing matches and the
    # engine has no early exit.
    text = '<a p="' + ("segment/" * 5_000) + 'x">'
    cred_filter = CredentialFilter()
    start = time.perf_counter()
    cred_filter.filter_text(text, filename="big.xml")
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"redaction went superlinear on one long token ({elapsed:.2f}s)"


def test_long_token_carrying_a_credential_marker_is_still_redacted():
    from intodoc.scanner.credential_filter import CredentialFilter

    prefix = "segment/" * 2_000
    text = f'<a p="{prefix}service_account.json">'
    cleaned = CredentialFilter().filter_text(text, filename="big.xml")
    assert "[CREDENTIAL_PATH]" in cleaned
    assert "service_account.json" not in cleaned
    assert prefix not in cleaned, "the whole token is replaced, not just the marker"


def test_credential_marker_is_matched_at_a_token_start_after_any_delimiter():
    from intodoc.scanner.credential_filter import CredentialFilter

    cred_filter = CredentialFilter()
    for text in (
        "keys/app.pem",
        '<file>secret.key</file>',
        "path=/etc/Credentials/x",
        'a="b" /opt/gcp.json',
    ):
        assert "[CREDENTIAL_PATH]" in cred_filter.filter_text(text, filename="t.xml"), text


# ── Credential PATH vs ordinary identifier ──────────────────────────────
#
# The marker used to be matched as a bare substring of any delimiter-free
# token, so a column named `key` and a business table named `*_CREDENTIALS`
# were redacted out of the SQL and tMap expressions that referenced them
# (verified on a real Talend estate). A credential path now has to prove it
# is a FILE reference.

def test_dataflow_identifiers_are_not_credential_paths():
    cred_filter = CredentialFilter()
    for text in (
        "row2.key",                                # column literally named "key"
        "input_row.key",
        "this.key",
        "row1.keyNumber",
        "configuration.dataset.keyValuePairs",
        "configuration.snowflakeAuth.keyAlias",
        "STG.PHARMACY_VP_CREDENTIALS",             # business table name
        "row23.pharmacy_vp_credentials",           # business column name
        "LoadCredentialsTable",
        "service_account_id",
    ):
        assert cred_filter.filter_text(text, filename="t.item") == text, text
        assert "credential_path" not in cred_filter.detect(text), text


def test_credential_file_references_are_still_redacted():
    cred_filter = CredentialFilter()
    for text in (
        "/etc/ssl/private/server.key",             # path-shaped
        r"C:\keys\prod.key",
        "keys/app.pem",
        "config/service_account.json",
        "/opt/Credentials/vault.item",
        "server.pem",                              # .pem needs no path
        "credentials.json",                        # stem names the material
        "MyCredentials.properties",
        "keystore.jks",
        "private_key.pem",
        "gcp.json",
        "secret.key",
    ):
        cleaned = cred_filter.filter_text(text, filename="t.item")
        assert "[CREDENTIAL_PATH]" in cleaned, text
        assert cred_filter.detect(text).get("credential_path"), text


def test_sql_and_expression_evidence_survives_redaction():
    """The scan is evidence: a credential-shaped NAME is not a secret."""
    cred_filter = CredentialFilter()
    for text in (
        '"SELECT id FROM STG.PHARMACY_VP_CREDENTIALS WHERE x=1"',
        'row2.key != null ? row2.key : ""',
        '<column name="pharmacy_vp_credentials" type="id_String"/>',
    ):
        assert cred_filter.filter_text(text, filename="t.item") == text, text


def test_a_redaction_placeholder_is_a_token_boundary():
    """Patterns must not read the output of the patterns that ran before.

    `[CREDENTIAL_PARAM_REDACTED]` contains the word CREDENTIAL; swallowing it
    turned an already correctly redacted URI into `[CREDENTIAL_PATH]`, and a
    path with a redacted segment must stay matchable on the other side of it.
    """
    cred_filter = CredentialFilter()
    assert cred_filter.filter_text(
        "jms://broker.example.nl:61616?password=FakeNotReal42",
    ) == "[URL_REDACTED]"
    assert "[CREDENTIAL_PATH]" in cred_filter.filter_text(
        r"\\srvt0156\share\certs\client.pem", filename="t.item",
    )


def test_credential_path_patterns_stay_linear_on_a_long_token():
    """Splitting one pattern into three must not reintroduce the quadratic
    scan the token-start anchor was added to kill. Times the credential-path
    patterns only -- other patterns have their own (pre-existing) costs on a
    pathological token, and this test is about this rule."""
    import time

    cred_filter = CredentialFilter()
    text = '<a p="' + ("segment." * 20_000) + 'key">'
    patterns = [
        pattern for pattern, replacement in cred_filter._active_patterns
        if replacement == "[CREDENTIAL_PATH]"
    ]
    assert len(patterns) == 3
    started = time.monotonic()
    for pattern in patterns:
        assert not pattern.search(text)
    assert time.monotonic() - started < 1.0
