"""Credential redaction engine -- runs on raw text BEFORE XML parsing."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from intodoc.config import RedactionLevel
from intodoc.models import RedactionDescriptor


def _is_redaction_placeholder(value: str) -> bool:
    """True for a bracketed placeholder such as ``[PASSWORD_REDACTED]``."""
    stripped = value.strip()
    return stripped.startswith("[") and stripped.endswith("]")


class CredentialFilter:
    """Redact sensitive data from raw file text.

    This MUST be applied before any parsing or LLM exposure.
    Platform-agnostic -- works for any platform.
    """

    # ── XML namespace / standard domains that should NEVER be redacted ──
    _SAFE_DOMAINS: frozenset[str] = frozenset({
        "w3.org", "omg.org", "eclipse.org", "xml.org", "xmlsoap.org",
        "apache.org", "sun.com", "java.com", "oracle.com", "microsoft.com",
        "xmlns.com", "talend.com", "talend.org", "schema.org", "purl.org",
        "lobster-world.com",
    })

    # xmlns declarations are structural XML identifiers, not data: redacting
    # their URIs breaks namespaced attribute lookups in every downstream
    # parser (e.g. xsi:type resolution). Their values are masked before any
    # pattern runs and restored verbatim afterwards.
    _XMLNS_DECL_RE = re.compile(
        r"\bxmlns(?::[A-Za-z_][\w.\-]*)?\s*=\s*(\"[^\"]*\"|'[^']*')"
    )

    # ── Known TLDs for FQDN matching ────────────────────────────────────
    _TLDS: str = (
        r"com|net|org|io|cloud|local|internal|dev|app|info|biz|co|eu|nl|de|uk|fr|be"
    )

    # Lobster-specific: only apply to .xml files (avoid false positives in non-XML text)
    _LOBSTER_BASE64_RE = re.compile(r"(<value>)([A-Za-z0-9+/]{8,}={0,2})(</value>)")

    # ── Credential-file references ──────────────────────────────────────
    #
    # A credential PATH is a FILE path, and proving that is the whole job of
    # these three patterns. A single pattern used to match these markers as a
    # bare substring anywhere inside a delimiter-free token, which destroyed
    # ordinary dataflow identifiers: verified on a real Talend estate,
    # `row2.key` (input table `row2`, column `key`), `this.key`,
    # `configuration.dataset.keyValuePairs` and the business table
    # `STG.PHARMACY_VP_CREDENTIALS` all became `[CREDENTIAL_PATH]`, taking
    # the SQL statements and tMap expressions that referenced them with them.
    # It also failed the post-scan verification gate outright: the scanner
    # COMPOSES `f"{table}.{column}"` for a mapper's offered fields
    # (`mapping_accounting`), so that token reaches the gate without ever
    # having passed through `filter_text`, the gate re-runs these same
    # detectors over it, and no scan output is written at all.
    #
    # Two independent proofs that a token is a file reference -- the same
    # shape of rule `is_sensitive_var_name` already applies to a bare "key"
    # name token, which is only sensitive when something qualifies it:
    #   1. the token carries a path separator, or
    #   2. the token is a filename whose own stem names credential material.
    # `.pem` additionally stands on its own (third pattern): that extension
    # exists only for certificate/key material, unlike `.key`, which is also
    # one of the most common column names there is.
    _CREDENTIAL_PATH_MARKER = (
        r"(?:credentials?|gcp\.json|service_account|\.pem|\.key)"
    )
    # Deliberately NOT `_SECRET_TOKENS`: that vocabulary is matched per NAME
    # TOKEN, and reusing it as a substring rule here would redact
    # `passthrough.json` and `tokenizer.properties`.
    _CREDENTIAL_STEM_MARKER = (
        r"(?:credentials?|secrets?|passwords?|keystore|truststore|"
        r"service_account|gcp|id_[rd]sa|api[_\-]?key|private[_\-]?key|oauth)"
    )
    # A closed vocabulary, like `_KNOWN_SCHEMES` and `_TLDS`: an open
    # `\.[A-Za-z]{1,8}` suffix rule would read the last segment of a JSON or
    # object path (`customer.credentials.name`) as a file extension.
    _CREDENTIAL_FILE_EXTENSION = (
        r"(?:pem|key|p12|pfx|jks|json|properties|ya?ml|xml|txt|cfg|conf|"
        r"ini|csv|crt|cer|der|pub|store|enc|dat|bak)"
    )
    # A redaction placeholder is a token BOUNDARY, not token content. These
    # patterns run after the ones that emit `[...]` placeholders, so without
    # excluding brackets they read their own output: verified, the word
    # CREDENTIAL inside `[CREDENTIAL_PARAM_REDACTED]` turned an already
    # correctly redacted `jms://host?password=...` URI into
    # `[CREDENTIAL_PATH]`. Treating a bracket as a boundary in the lookbehind
    # too is what keeps `\\[HOSTNAME]\share\certs\client.pem` redactable --
    # excluding it from the runs alone would leave that path unmatchable.
    _PATH_TOKEN_CHAR = r"[^\s\"'<>\[\]]"

    # ── Compiled patterns per level ─────────────────────────────────────
    # Each entry: (regex, replacement, min_level)
    _BASE_PATTERNS: list[tuple[re.Pattern[str], str, RedactionLevel]] = [
        # Talend encrypted passwords
        (re.compile(r"enc:system\.encryption\.key\.v\d+:[^\s\"'<>]+"),
         "[ENCRYPTED_PASSWORD]", RedactionLevel.STANDARD),
        # id_Password field values in XML
        (re.compile(
            r'(<elementParameter\s+field="[^"]*"\s+name="id_Password"\s+value=")[^"]*(")',
            re.IGNORECASE,
        ), r'\1[PASSWORD_REDACTED]\2', RedactionLevel.STANDARD),
        # Alternative password param ordering
        (re.compile(
            r'(<elementParameter\s+[^>]*name="id_Password"[^>]*value=")[^"]*(")',
            re.IGNORECASE,
        ), r'\1[PASSWORD_REDACTED]\2', RedactionLevel.STANDARD),
        # IP addresses (but not version-like patterns e.g. 1.2.3)
        (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
         "[SERVER_IP]", RedactionLevel.STANDARD),
        # JDBC URLs with embedded credentials
        (re.compile(r"jdbc:[a-zA-Z]+://[^\s\"'<>]*:[^\s\"'<>]*@[^\s\"'<>]+"),
         "[CONNECTION_STRING_REDACTED]", RedactionLevel.STANDARD),
        # Generic connection strings with user:pass@
        (re.compile(r"://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+"),
         "[CONNECTION_STRING_REDACTED]", RedactionLevel.STANDARD),
        # Credential query-parameters inside URI/code strings. Verified leak:
        # a Camel FTP URI built from concatenated Java strings carried
        # `?password=RAW(<plaintext>)&fileName=...`; the URL pattern redacted
        # the host string but the query fragment lived in a SEPARATE string
        # literal and survived. Query-string context (`?`/`&`/`;` before the
        # key) is required so ordinary code assignments such as
        # `String password = decoded.substring(0, i)` are never mangled.
        (re.compile(
            r"([?&;](?:amp;)?\s*(?:password|passwd|pwd|secret|token|apikey|"
            r"api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|"
            r"auth[_-]?token|passphrase|credential)\s*=\s*)"
            r"(?:RAW\([^)\n]*\)|(?!\[)[^\s&\"'<>;,\n]+)",
            re.IGNORECASE,
        ), r"\1[CREDENTIAL_PARAM_REDACTED]", RedactionLevel.STANDARD),
        # Camel `key=RAW(value)` wrapper outside query-string context: RAW()
        # exists precisely to mark a literal (usually secret) value, so a
        # credential key with a RAW value is a leak by definition.
        (re.compile(
            r"(\b(?:password|passwd|pwd|secret|token|apikey|api[_-]?key|"
            r"client[_-]?secret|access[_-]?token|refresh[_-]?token|"
            r"auth[_-]?token|passphrase|credential)\s*=\s*)RAW\([^)\n]*\)",
            re.IGNORECASE,
        ), r"\1[CREDENTIAL_PARAM_REDACTED]", RedactionLevel.STANDARD),
        # Credential file paths (always, even at standard). See the marker
        # vocabularies above for why this is three patterns and not one.
        #
        # The leading `(?<![^\s"'<>])` anchors each match to the START of a
        # delimiter-free token and is load-bearing for performance, not style.
        # Without it the two unbounded `[^\s"'<>]*` runs around the alternation
        # are retried at every position inside every token, which is quadratic
        # in token length: measured on a real Talend estate, one 16 KB metadata
        # file cost 1.08s for ZERO matches and `order_load_0.1.item` cost 60.3s.
        # `filter_text` runs these patterns once per file and `detect_residual`
        # twice more for XML, so a full sanitized-workspace pass over 6,768
        # files took 89.6s in this pattern alone; anchored it takes 1.62s with
        # byte-identical output on every one of those files.
        #
        # 1. Path-shaped: the token carries a path separator. The lookahead
        #    proves that before the unbounded runs are entered, so a token
        #    without one is rejected in a single linear scan.
        (re.compile(
            r"(?<!" + _PATH_TOKEN_CHAR + r")(?=" + _PATH_TOKEN_CHAR + r"*[\\/])"
            + _PATH_TOKEN_CHAR + r"*" + _CREDENTIAL_PATH_MARKER
            + _PATH_TOKEN_CHAR + r"*",
            re.IGNORECASE,
        ), "[CREDENTIAL_PATH]", RedactionLevel.STANDARD),
        # 2. Bare filename whose stem names credential material
        #    (`credentials.json`, `keystore.jks`, `secret.key`). The required
        #    file extension is what keeps `STG.PHARMACY_VP_CREDENTIALS` and
        #    `LoadCredentialsTable` out.
        (re.compile(
            r"(?<!" + _PATH_TOKEN_CHAR + r")" + _PATH_TOKEN_CHAR + r"*"
            + _CREDENTIAL_STEM_MARKER + _PATH_TOKEN_CHAR + r"*\."
            + _CREDENTIAL_FILE_EXTENSION + r"\b",
            re.IGNORECASE,
        ), "[CREDENTIAL_PATH]", RedactionLevel.STANDARD),
        # 3. `.pem` is credential material by extension alone.
        (re.compile(
            r"(?<!" + _PATH_TOKEN_CHAR + r")" + _PATH_TOKEN_CHAR + r"*\.pem\b",
            re.IGNORECASE,
        ), "[CREDENTIAL_PATH]", RedactionLevel.STANDARD),
        # X509 certificate blocks
        (re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"),
         "", RedactionLevel.STANDARD),
        # Private key blocks
        (re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----"),
         "", RedactionLevel.STANDARD),

        # ── New standard-level patterns ─────────────────────────────
        # Email addresses
        (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
         "[EMAIL_REDACTED]", RedactionLevel.STANDARD),
        # URLs with protocol -- handled by _filter_urls() so safe domains
        # (XML namespace hosts) are excluded at runtime, like FQDNs below.
        # FQDNs -- matched against known TLDs, safe domains excluded at runtime
        # This is a placeholder; actual FQDN filtering uses _filter_fqdns()

        # ── HTTP authentication schemes ─────────────────────────────────────
        # Full Authorization header value — must come before bare Bearer pattern
        (re.compile(r"(?i)\bAuthorization\s*[:=]\s*\S+\s+[A-Za-z0-9._+/=\-]{10,}"),
         "[AUTH_HEADER_REDACTED]", RedactionLevel.STANDARD),
        # Bearer tokens (standalone, without Authorization prefix)
        (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._+/=\-]{10,}"),
         "[BEARER_TOKEN_REDACTED]", RedactionLevel.STANDARD),
        # Basic auth (base64 encoded user:pass)
        (re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]{10,}"),
         "[BASIC_AUTH_REDACTED]", RedactionLevel.STANDARD),
        # Custom API key header values
        (re.compile(
            r"(?i)\b(?:X-API-Key|X-Auth-Token|Api-Key|X-Access-Token|X-Token|X-Client-Secret)\s*[:=]\s*[A-Za-z0-9._+/=\-]{10,}"
        ), "[API_KEY_REDACTED]", RedactionLevel.STANDARD),

        # ── JWT tokens (three-part base64url) ────────────────────────────────
        (re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
         "[JWT_REDACTED]", RedactionLevel.STANDARD),

        # ── Source-control platform tokens ───────────────────────────────────
        # GitHub PATs (ghp_, gho_, ghs_, ghr_, ghu_, ghx_) and fine-grained PATs
        (re.compile(r"\bgh[phosrux]_[A-Za-z0-9_]{10,}\b|\bgithub_pat_[A-Za-z0-9_]{10,}\b"),
         "[GITHUB_TOKEN_REDACTED]", RedactionLevel.STANDARD),
        # GitLab PATs / project tokens
        (re.compile(r"\bglpat-[A-Za-z0-9_\-]{10,}\b|\bglptt-[A-Za-z0-9_\-]{10,}\b"),
         "[GITLAB_TOKEN_REDACTED]", RedactionLevel.STANDARD),
        # NPM access tokens
        (re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
         "[NPM_TOKEN_REDACTED]", RedactionLevel.STANDARD),
        # PyPI API tokens
        (re.compile(r"\bpypi-[A-Za-z0-9_\-]{40,}\b"),
         "[PYPI_TOKEN_REDACTED]", RedactionLevel.STANDARD),

        # ── Cloud provider credentials ────────────────────────────────────────
        # AWS access key IDs (AKIA, ASIA, AROA, ANPA, ANVA, AIDA prefixes)
        (re.compile(r"\b(?:AKIA|ASIA|AROA|ANPA|ANVA|AIDA)[0-9A-Z]{16}\b"),
         "[AWS_ACCESS_KEY_REDACTED]", RedactionLevel.STANDARD),
        # AWS secret access keys (keyword-anchored to avoid false positives)
        (re.compile(
            r"(?i)\baws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*[\"']?[A-Za-z0-9+/]{40}[\"']?"
        ), "[AWS_SECRET_KEY_REDACTED]", RedactionLevel.STANDARD),
        # GCP / Google API keys (AIzaSy prefix)
        (re.compile(r"\bAIzaSy[A-Za-z0-9_\-]{33}\b"),
         "[GCP_API_KEY_REDACTED]", RedactionLevel.STANDARD),
        # Firebase server keys (AAAA prefix)
        (re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b"),
         "[FIREBASE_KEY_REDACTED]", RedactionLevel.STANDARD),
        # Azure storage account keys
        (re.compile(r"(?i)\bAccountKey\s*=\s*[A-Za-z0-9+/]{40,}={0,2}"),
         "[AZURE_ACCOUNT_KEY_REDACTED]", RedactionLevel.STANDARD),
        # Databricks personal access tokens
        (re.compile(r"\bdapi[a-f0-9]{32}\b"),
         "[DATABRICKS_TOKEN_REDACTED]", RedactionLevel.STANDARD),

        # ── AI / LLM provider keys ────────────────────────────────────────────
        # OpenAI / Anthropic / generic sk- keys
        (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b"),
         "[LLM_API_KEY_REDACTED]", RedactionLevel.STANDARD),

        # ── Communication & SaaS provider keys ───────────────────────────────
        # Slack bot/user/app tokens
        (re.compile(r"\bxox[bpaos]-[0-9A-Za-z\-]{10,}\b"),
         "[SLACK_TOKEN_REDACTED]", RedactionLevel.STANDARD),
        # Stripe keys (live and test, secret and publishable)
        (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
         "[STRIPE_KEY_REDACTED]", RedactionLevel.STANDARD),
        # SendGrid API keys
        (re.compile(r"\bSG\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
         "[SENDGRID_KEY_REDACTED]", RedactionLevel.STANDARD),
        # Twilio SIDs / auth tokens
        (re.compile(r"\b(?:AC|SK)[a-f0-9]{32}\b"),
         "[TWILIO_KEY_REDACTED]", RedactionLevel.STANDARD),
        # Mailgun API keys
        (re.compile(r"\bkey-[a-f0-9]{32}\b"),
         "[MAILGUN_KEY_REDACTED]", RedactionLevel.STANDARD),
        # HubSpot private app tokens
        (re.compile(r"\bpat-[a-z]{2}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
         "[HUBSPOT_TOKEN_REDACTED]", RedactionLevel.STANDARD),

        # ── Lobster-specific patterns ────────────────────────────────
        # OBF-encoded passwords (Lobster obfuscation format)
        (re.compile(r"OBF:[a-zA-Z0-9+/=]+"),
         "[OBF_PASSWORD_REDACTED]", RedactionLevel.STANDARD),
        # Base64-encoded value tags (Lobster filter constants) — XML-only, guarded in filter_text
        (_LOBSTER_BASE64_RE,
         r"\1[BASE64_REDACTED]\3", RedactionLevel.STRICT),

        # ── Strict-level patterns ───────────────────────────────────
        # Windows file paths (C:\..., D:\...)
        (re.compile(r"[A-Za-z]:\\(?:[^\s\"'<>\\]+\\)*[^\s\"'<>\\]*"),
         "[FILE_PATH_REDACTED]", RedactionLevel.STRICT),
        # Unix sensitive paths (/home/, /opt/, /var/, /etc/, /srv/, /tmp/)
        (re.compile(r"/(?:home|opt|var|etc|srv|tmp|usr/local)/[^\s\"'<>]*"),
         "[FILE_PATH_REDACTED]", RedactionLevel.STRICT),
    ]

    # URL pattern (applied separately for safe-domain exclusion)
    # Every URI scheme that `describe_value()` can safely characterise must
    # also be redacted as a complete URI.  Keeping this smaller than a generic
    # ``word://`` matcher is intentional: an arbitrary token that happens to
    # contain a colon must never be treated as a protocol fact.  The previous
    # expression omitted JMS, which both leaked query-string credentials and
    # made the verification gate blind to them.
    _URL_RE = re.compile(
        r"(?:https?|wss?|jdbc(?::[A-Za-z][A-Za-z0-9+.\-]*)?|jms|amqps?|"
        r"s?ftp|ftpes|tcp|smtps?|ldaps?|mqtt|stomp|file)://"
        r"(?:(?!&(?:quot|apos|#34|#39);)[^\s\"'<>])+",
        re.IGNORECASE,
    )
    _URL_HOST_RE = re.compile(
        r"^[a-z][a-z0-9+.\-]*://(?:[^/@\s]*@)?([^/:?#\s]+)",
        re.IGNORECASE,
    )

    # FQDN pattern (applied separately for safe-domain exclusion)
    _FQDN_RE = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+("
        + r"com|net|org|io|cloud|local|internal|dev|app|info|biz|co|eu|nl|de|uk|fr|be"
        + r")\b",
        re.IGNORECASE,
    )

    # UNC / share-path hosts WITHOUT a dot-TLD (e.g. \\srvt0156\share,
    # //fileserver01/share). The FQDN pattern requires a known TLD, so bare
    # intranet hostnames escaped redaction entirely and reached published
    # docs. Lookbehind excludes ://  (URLs), escaped-JSON \\\\ noise and
    # inline code like a//b; lookahead requires a path separator + segment.
    _UNC_HOST_RE = re.compile(
        r"(?<![\w:/\\])(\\\\|//)([A-Za-z][\w\-]*)(?=[\\/][^\s\"'<>\\/])"
    )

    # Key names whose values should be redacted (case-insensitive match)
    _SENSITIVE_KEYS = frozenset({
        "password", "secret", "token", "apikey", "api_key",
        "bearer", "client_secret", "private_key", "access_key",
        "authorization", "x-api-key", "x-auth-token", "x-access-token",
    })

    # Pattern for XML-style key=value where key is sensitive
    _SENSITIVE_KV = re.compile(
        r'((?:name|field|key)\s*=\s*"(?:' +
        "|".join(_SENSITIVE_KEYS) +
        r')"[^>]*value\s*=\s*")[^"]*(")',
        re.IGNORECASE,
    )

    # ── Variable name tokens that indicate sensitive values ─────────
    # Names are tokenized on underscores, hyphens, dots, whitespace AND
    # camelCase boundaries, so "MaximoPassword", "maximo_password" and
    # "AES_Key" are all recognized. Suffix-only matching missed camelCase
    # names entirely and let cleartext secrets through to scan output.
    _SECRET_TOKENS = frozenset({
        "password", "passwd", "pwd", "pass", "secret", "secrets",
        "credential", "credentials", "bearer", "apikey", "token", "tokens",
    })
    # "key" is only sensitive when qualified by a crypto/auth token right
    # before it: AES_Key, API_Key, AuthenticationKey, private_key -- but
    # NOT KeyColumn, PrimaryKey, BusinessKey.
    _KEY_QUALIFIER_TOKENS = frozenset({
        "aes", "api", "auth", "authentication", "access", "private",
        "client", "encryption", "signing", "hmac", "ssh", "rsa", "jwt",
        "license", "session", "security",
    })
    _INFRA_TOKENS = frozenset({
        "user", "username", "host", "hostname", "server",
        "url", "endpoint", "broker", "uri",
    })

    # Name tokenizer: split on separators, then on camelCase boundaries
    # (lower->Upper and ACRONYMWord boundaries like "logDB" -> log, DB).
    _NAME_SEPARATOR_RE = re.compile(r"[_\-.\s]+")
    _CAMEL_BOUNDARY_RE = re.compile(
        r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"
    )

    # ── Redaction descriptor extraction ("mask-and-CAPTURE") ─────────
    #
    # `describe_value` runs on a value BEFORE it is redacted and returns a
    # RedactionDescriptor holding ONLY provably-non-sensitive structural
    # facts. It never returns the host, path, query string, username, or
    # any credential value -- only enums/booleans/known scheme tokens. Any
    # fact that cannot be safely determined is left None.

    # Scheme must come from this fixed vocabulary. This is the key safety
    # guard: an arbitrary "word:" prefix on an unrelated secret string
    # (e.g. a token that happens to contain a colon) is NEVER reported as a
    # scheme -- only recognized protocol tokens are.
    _KNOWN_SCHEMES: frozenset[str] = frozenset({
        "https", "http", "ws", "wss", "jdbc", "jms", "ftp", "ftps", "ftpes",
        "sftp", "smtp", "smtps", "ldap", "ldaps", "amqp", "amqps", "mqtt",
        "stomp", "file", "mailto", "tcp",
    })
    _TLS_SCHEMES: frozenset[str] = frozenset({
        "https", "ftps", "ftpes", "smtps", "ldaps", "amqps", "wss", "sftp",
    })
    _NO_TLS_SCHEMES: frozenset[str] = frozenset({
        "http", "ftp", "jms", "ldap", "smtp", "ws", "tcp", "mqtt",
    })
    _CATEGORY_BY_SCHEME: dict[str, str] = {
        "https": "rest", "http": "rest", "ws": "rest", "wss": "rest",
        "jdbc": "db",
        "jms": "jms", "amqp": "jms", "amqps": "jms", "mqtt": "jms", "stomp": "jms",
        "smtp": "smtp", "smtps": "smtp", "mailto": "smtp",
        "sftp": "file", "ftp": "file", "ftps": "file", "ftpes": "file", "file": "file",
        "ldap": "directory", "ldaps": "directory",
    }

    _SCHEME_PREFIX_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]{0,15}):")
    _AUTHORITY_RE = re.compile(
        r"^//(?:(?P<userinfo>[^@/?#\s]+)@)?(?P<host>[^/:?#\s]+)"
    )
    # Query/param key names that indicate an auth credential is present.
    # Only the KEY NAME is inspected here, never the value on the right of
    # "=" -- that value is exactly the credential we must not leak.
    _AUTH_PARAM_NAME_RE = re.compile(
        r"(?i)(?:^|[;&?])\s*"
        r"(password|pwd|pass|secret|token|api[_-]?key|apikey|"
        r"access[_-]?token|client[_-]?secret|oauth|bearer)\s*="
    )
    # ssl/tls/encrypt flags are structural booleans, not secrets -- reading
    # their literal true/false value is safe, unlike a credential value.
    _TLS_FLAG_RE = re.compile(
        r"(?i)(?:^|[;&?])\s*(ssl|usessl|use_ssl|tls|encrypt)\s*=\s*(true|false)\b"
    )
    _BEARER_HEADER_RE = re.compile(r"(?i)\bBearer\s+\S+")
    _BASIC_HEADER_RE = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+\b")

    # An opaque, process-local marker transports a *safe descriptor* across
    # Layer 1's required-before-parse redaction boundary.  Parser code turns
    # the marker back into the ordinary URL placeholder before anything is
    # persisted.  It is deliberately not derived from the original value.
    _DESCRIPTOR_TOKEN_RE = re.compile(r"\[INTODOC_URI_DESCRIPTOR_(\d+)\]")
    _URI_USERINFO_RE = re.compile(r"://[^/@\s]+:[^/@\s]+@")

    @classmethod
    def describe_value(cls, value: str, *, is_host: bool = False) -> RedactionDescriptor | None:
        """Extract safe structural facts from `value` BEFORE it is redacted.

        Returns None when nothing can be safely determined. Every returned
        field is an enum/bool/known-scheme-token -- never a host, path,
        query string, username, or credential value.

        `is_host` must only be set by a caller that already knows -- from
        the field's own semantics, not from guessing at the value's shape
        -- that this value is a bare host/IP (e.g. MetadataConnection.host).
        An arbitrary opaque secret can easily look hostname-shaped (plain
        alphanumerics), so this is never inferred automatically from the
        value's characters alone; without this flag an un-schemed value
        with no other signal returns None.
        """
        if not isinstance(value, str):
            return None
        text = value.strip()
        if not text:
            return None

        scheme: str | None = None
        category: str | None = None
        auth_present: bool | None = None
        auth_type: str | None = None
        tls: bool | None = None
        host_present: bool | None = None

        scheme_match = cls._SCHEME_PREFIX_RE.match(text)
        if scheme_match and scheme_match.group(1).lower() in cls._KNOWN_SCHEMES:
            scheme = scheme_match.group(1).lower()
            remainder = text[scheme_match.end():]
            if scheme == "jdbc":
                # jdbc:<subprotocol>://... -- locate the authority section
                # after the subprotocol token, which is discarded (not
                # reported) since it is not part of the known vocabulary.
                sub_scheme_match = cls._SCHEME_PREFIX_RE.match(remainder)
                if sub_scheme_match:
                    remainder = remainder[sub_scheme_match.end():]
            authority_match = cls._AUTHORITY_RE.match(remainder)
            if authority_match:
                host_present = bool(authority_match.group("host"))
                userinfo = authority_match.group("userinfo")
                if userinfo:
                    auth_present = True
                    auth_type = "basic" if ":" in userinfo else "unknown"
            category = cls._CATEGORY_BY_SCHEME.get(scheme)
            if scheme in cls._TLS_SCHEMES:
                tls = True
            elif scheme in cls._NO_TLS_SCHEMES:
                tls = False

        if auth_present is not True:
            name_match = cls._AUTH_PARAM_NAME_RE.search(text)
            if name_match:
                auth_present = True
                key = name_match.group(1).lower()
                if "api" in key:
                    auth_type = "api_key"
                elif "oauth" in key or "bearer" in key:
                    auth_type = "oauth"
                elif key in ("password", "pwd", "pass"):
                    auth_type = "basic"
                else:
                    auth_type = auth_type or "unknown"

        if cls._BEARER_HEADER_RE.search(text):
            auth_present = True
            auth_type = "bearer"
        elif auth_type != "bearer" and cls._BASIC_HEADER_RE.search(text):
            auth_present = True
            auth_type = "basic"

        if auth_present is None and scheme is not None:
            # A well-formed, recognized connection value with no credential
            # signal at all -- explicit "no auth detected", not a guess.
            auth_present = False
            auth_type = "none"

        tls_flag_match = cls._TLS_FLAG_RE.search(text)
        if tls_flag_match:
            tls = tls_flag_match.group(2).lower() == "true"

        if is_host and scheme is None and host_present is None:
            # Caller already knows (by field semantics) that this whole
            # value IS a host -- e.g. MetadataConnection.host. Only
            # host_present can be safely reported; nothing else is
            # determinable from a bare host string.
            host_present = True

        if (
            scheme is None and category is None and auth_present is None
            and tls is None and host_present is None
        ):
            return None

        return RedactionDescriptor(
            scheme=scheme,
            category=category,
            auth_present=auth_present,
            auth_type=auth_type,
            tls=tls,
            host_present=host_present,
        )

    def __init__(
        self,
        level: RedactionLevel = RedactionLevel.STANDARD,
        config_path: Path | None = None,
    ) -> None:
        self._level = level
        self._audit: dict[str, list[str]] = defaultdict(list)  # category -> [sha256 hashes]
        self._redaction_descriptors: dict[str, RedactionDescriptor] = {}
        self._redaction_token_placeholders: dict[str, str] = {}
        self._next_descriptor_token = 1
        self._custom_patterns: list[tuple[re.Pattern[str], str, RedactionLevel]] = []
        self._custom_safe_domains: set[str] = set()
        self._custom_sensitive_vars: list[str] = []

        if config_path and config_path.exists():
            self._load_custom_config(config_path)

        # Build level-filtered pattern list
        self._active_patterns = [
            (pat, repl) for pat, repl, min_level in self._BASE_PATTERNS
            if self._level_includes(min_level)
        ] + [
            (pat, repl) for pat, repl, min_level in self._custom_patterns
            if self._level_includes(min_level)
        ]

    @property
    def level(self) -> RedactionLevel:
        return self._level

    @property
    def cache_fingerprint(self) -> str:
        """Stable identity of every effective redaction input.

        Audit counters and generated descriptor tokens are deliberately absent:
        they record execution but do not configure the filtered output.
        """
        payload = {
            # This version is part of every content-addressed parse-cache key.
            # v4 adds descriptor-aware URI redaction, so v3 parse results must
            # never be replayed into a current scan.
            "contract": "credential-filter-v4",
            "level": self._level.value,
            "patterns": [
                {"pattern": pattern.pattern, "flags": pattern.flags, "replacement": replacement}
                for pattern, replacement in self._active_patterns
            ],
            "safe_domains": sorted(self._SAFE_DOMAINS | self._custom_safe_domains),
            "sensitive_variables": sorted(self._custom_sensitive_vars),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _level_includes(self, min_level: RedactionLevel) -> bool:
        """Check if current level includes patterns at min_level."""
        order = {RedactionLevel.STANDARD: 0, RedactionLevel.STRICT: 1, RedactionLevel.PARANOID: 2}
        return order[self._level] >= order[min_level]

    def _load_custom_config(self, path: Path) -> None:
        """Load custom redaction rules from .intodoc-redact.yaml."""
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return
        except Exception:
            return

        # Custom regex patterns
        for entry in data.get("patterns", []):
            if "regex" in entry and "replacement" in entry:
                level_str = entry.get("level", "standard")
                try:
                    level = RedactionLevel(level_str)
                except ValueError:
                    level = RedactionLevel.STANDARD
                try:
                    compiled = re.compile(entry["regex"])
                    self._custom_patterns.append((compiled, entry["replacement"], level))
                except re.error:
                    pass

        # Custom safe domains
        for domain in data.get("safe_domains", []):
            if isinstance(domain, str):
                self._custom_safe_domains.add(domain.lower())

        # Custom sensitive variable name patterns
        for var_pat in data.get("sensitive_vars", []):
            if isinstance(var_pat, str):
                self._custom_sensitive_vars.append(var_pat.lower())

    def _record_redaction(self, category: str, original: str) -> None:
        """Record a redaction for the audit report (hash only, never raw value)."""
        h = hashlib.sha256(original.encode("utf-8", errors="replace")).hexdigest()[:16]
        self._audit[category].append(h)

    def _is_safe_domain(self, fqdn: str) -> bool:
        """Check if an FQDN is a safe (XML namespace / standard) domain."""
        fqdn_lower = fqdn.lower()
        for safe in self._SAFE_DOMAINS | self._custom_safe_domains:
            if fqdn_lower == safe or fqdn_lower.endswith("." + safe):
                return True
        return False

    def _filter_fqdns(self, text: str) -> str:
        """Replace FQDNs with [HOSTNAME], preserving safe domains."""
        def _replace_fqdn(m: re.Match[str]) -> str:
            fqdn = m.group(0)
            if self._is_safe_domain(fqdn):
                return fqdn
            self._record_redaction("fqdn", fqdn)
            return "[HOSTNAME]"
        return self._FQDN_RE.sub(_replace_fqdn, text)

    def _descriptor_token(self, descriptor: RedactionDescriptor, placeholder: str) -> str:
        token = f"[INTODOC_URI_DESCRIPTOR_{self._next_descriptor_token}]"
        self._next_descriptor_token += 1
        self._redaction_descriptors[token] = descriptor
        self._redaction_token_placeholders[token] = placeholder
        return token

    def descriptor_from_redaction_token(self, value: str) -> RedactionDescriptor | None:
        """Return a Layer-1 URI descriptor for one exact opaque marker.

        The raw URI has already been discarded.  Callers must not attempt to
        infer a descriptor from a substring or a redacted placeholder: only
        an exact marker created during this scan is authoritative.
        """
        if not isinstance(value, str):
            return None
        return self._redaction_descriptors.get(value.strip())

    def normalize_redaction_tokens(self, value: str) -> str:
        """Replace internal descriptor markers with the public URL placeholder."""
        def replacement(match: re.Match[str]) -> str:
            token = match.group(0)
            return self._redaction_token_placeholders.get(token, "[URL_REDACTED]")
        return self._DESCRIPTOR_TOKEN_RE.sub(replacement, value)

    def normalize_model_tokens(self, value: object) -> object:
        """Remove private descriptor tokens from a parsed model tree in place.

        Descriptor tokens are a short-lived transport between raw-text
        filtering and exact parser fields. They are process-local and must
        never enter a cache or a public parsed model: a later process cannot
        recover their placeholder semantics. Exact fields consume their
        descriptor before this pass; every remaining string is normalized to
        its public redaction placeholder.
        """
        # Str-backed enums satisfy ``isinstance(value, str)``. Preserve their
        # model type rather than replacing them with plain strings.
        if isinstance(value, Enum):
            return value
        if isinstance(value, str):
            return self.normalize_redaction_tokens(value)
        if isinstance(value, BaseModel):
            for field_name in type(value).model_fields:
                setattr(
                    value,
                    field_name,
                    self.normalize_model_tokens(getattr(value, field_name)),
                )
            return value
        if isinstance(value, list):
            for index, item in enumerate(value):
                value[index] = self.normalize_model_tokens(item)
            return value
        if isinstance(value, dict):
            for key, item in list(value.items()):
                value[key] = self.normalize_model_tokens(item)
            return value
        return value

    def _filter_urls(self, text: str, *, capture_descriptors: bool = False) -> str:
        """Replace known-scheme URIs with a descriptor marker or URL placeholder.

        This runs before general text patterns so a complete URI (including
        userinfo/query credentials) is handled as one unit rather than being
        partially mangled by a connection-string regex.
        """
        def _replace_url(m: re.Match[str]) -> str:
            url = m.group(0)
            host_match = self._URL_HOST_RE.match(url)
            descriptor = self.describe_value(url)
            # XML namespace URLs are safely protected before this method is
            # reached.  A safe-domain *data* URL must still be redacted when
            # it carries userinfo or a credential-shaped query parameter.
            if (
                host_match
                and self._is_safe_domain(host_match.group(1))
                and (descriptor is None or descriptor.auth_present is not True)
            ):
                return url
            self._record_redaction("url_redacted", url)
            if capture_descriptors and descriptor is not None:
                # Retain the established output redaction shape after the
                # parser consumes the token.  A URL with user:password@ was
                # historically represented by CONNECTION_STRING_REDACTED;
                # query-auth URIs stay URL_REDACTED.
                placeholder = (
                    "[CONNECTION_STRING_REDACTED]"
                    if self._URI_USERINFO_RE.search(url)
                    else "[URL_REDACTED]"
                )
                return self._descriptor_token(descriptor, placeholder)
            return "[URL_REDACTED]"
        return self._URL_RE.sub(_replace_url, text)

    def _filter_unc_hosts(self, text: str) -> str:
        """Replace bare hostnames in UNC/share paths with [HOSTNAME].

        Path structure is preserved: \\\\srvt0156\\share\\x becomes
        \\\\[HOSTNAME]\\share\\x. Hosts matching a safe domain survive.
        """
        def _replace_host(m: re.Match[str]) -> str:
            host = m.group(2)
            if self._is_safe_domain(host):
                return m.group(0)
            self._record_redaction("unc_host", host)
            return m.group(1) + "[HOSTNAME]"
        return self._UNC_HOST_RE.sub(_replace_host, text)

    def _mask_xmlns_decls(self, text: str) -> tuple[str, list[str]]:
        """Replace xmlns declaration values with placeholders before redaction."""
        masked: list[str] = []

        def _mask(m: re.Match[str]) -> str:
            masked.append(m.group(1))
            decl = m.group(0)
            return decl[: -len(m.group(1))] + f'"__INTODOC_XMLNS_{len(masked) - 1}__"'

        return self._XMLNS_DECL_RE.sub(_mask, text), masked

    @staticmethod
    def _restore_xmlns_decls(text: str, masked: list[str]) -> str:
        """Restore xmlns declaration values masked by _mask_xmlns_decls."""
        for i, value in enumerate(masked):
            text = text.replace(f'"__INTODOC_XMLNS_{i}__"', value)
        return text

    def filter_text(
        self,
        text: str,
        filename: str = "",
        *,
        capture_uri_descriptors: bool = False,
    ) -> str:
        """Apply all redaction patterns to raw text. Returns cleaned text."""
        # Internal markers are only allowed between Layer 1 and the Talend
        # parser's exact-field descriptor attachment. Any later filtering pass
        # must erase them, including values embedded in expressions or model
        # fields that do not have a descriptor slot.
        if not capture_uri_descriptors:
            text = self.normalize_redaction_tokens(text)
        is_xml = self.is_xml_text(text, filename)
        xmlns_values: list[str] = []
        if is_xml:
            text, xmlns_values = self._mask_xmlns_decls(text)
        # A source parser can opt into this private, pre-parse transport of
        # descriptors.  Public/default filtering retains the established
        # placeholder shapes and performs URL cleanup after generic patterns.
        # Either path covers the full URI before it can be persisted.
        if capture_uri_descriptors and self._level_includes(RedactionLevel.STANDARD):
            text = self._filter_urls(text, capture_descriptors=True)

        for pattern, replacement in self._active_patterns:
            if pattern is self._LOBSTER_BASE64_RE and not is_xml:
                continue
            # Use a wrapper to track audit for patterns with simple replacements
            def _make_repl(pat: re.Pattern[str], repl: str):  # noqa: E301
                def _repl(m: re.Match[str]) -> str:
                    original = m.group(0)
                    # Determine category from replacement tag
                    cat = repl.strip("[]").lower() if repl.startswith("[") else "other"
                    self._record_redaction(cat, original)
                    # Handle backreferences
                    if "\\" in repl or r"\1" in repl:
                        return m.expand(repl)
                    return repl
                return _repl

            text = pattern.sub(_make_repl(pattern, replacement), text)

        # Sensitive key-value pairs
        def _kv_repl(m: re.Match[str]) -> str:
            self._record_redaction("sensitive_kv", m.group(0))
            return m.group(1) + "[REDACTED]" + m.group(2)

        text = self._SENSITIVE_KV.sub(_kv_repl, text)

        # FQDN and UNC-host filtering (standard+), safe domains preserved.
        # In descriptor-capture mode URLs were already replaced as a complete
        # unit before generic patterns; otherwise preserve the historic
        # ordering and emit the public URL placeholder here.
        if self._level_includes(RedactionLevel.STANDARD):
            if not capture_uri_descriptors:
                text = self._filter_urls(text)
            text = self._filter_fqdns(text)
            text = self._filter_unc_hosts(text)

        if xmlns_values:
            text = self._restore_xmlns_decls(text, xmlns_values)

        return text

    @classmethod
    def tokenize_name(cls, name: str) -> list[str]:
        """Split a variable/param name into lowercase tokens.

        Splits on underscores, hyphens, dots and whitespace, then on
        camelCase boundaries: "MaximoPassword" -> [maximo, password],
        "connection_logDB_Username" -> [connection, log, db, username].
        """
        tokens: list[str] = []
        for chunk in cls._NAME_SEPARATOR_RE.split(name):
            if not chunk:
                continue
            tokens.extend(p for p in cls._CAMEL_BOUNDARY_RE.split(chunk) if p)
        return [t.lower() for t in tokens]

    def is_sensitive_var_name(self, name: str) -> bool:
        """Check if a context variable name indicates a sensitive value.

        Token-based: matches camelCase, snake_case, kebab-case and exact
        names uniformly. Returns True for password/secret/key vars at all
        levels, and for infra vars (user, host, url, ...) at strict+.
        """
        name_lower = name.lower()
        tokens = self.tokenize_name(name)

        # Secret tokens anywhere in the name: password, secret, token, ...
        if any(t in self._SECRET_TOKENS for t in tokens):
            return True

        # "key"/"keys" only when the preceding token qualifies it as a
        # crypto/auth key (AES_Key, API_Key, AuthenticationKey) -- plain
        # KeyColumn / PrimaryKey / BusinessKey stay untouched.
        for i, t in enumerate(tokens):
            if t in ("key", "keys") and i > 0 and tokens[i - 1] in self._KEY_QUALIFIER_TOKENS:
                return True

        # id_Password type (Talend convention)
        if name_lower == "id_password":
            return True

        # Custom sensitive var patterns
        for pat in self._custom_sensitive_vars:
            if pat in name_lower:
                return True

        # Infrastructure vars: only at strict+
        if self._level_includes(RedactionLevel.STRICT):
            if any(t in self._INFRA_TOKENS for t in tokens):
                return True

        return False

    def has_credentials(self, text: str) -> bool:
        """Quick check if text likely contains credentials."""
        return bool(self.detect(text))

    @classmethod
    def is_xml_text(cls, text: str, filename: str = "") -> bool:
        """Whether this content is treated as XML by the filter.

        Single definition of the rule: `filter_text` protects xmlns
        declarations and enables the XML-only patterns based on it, and a
        gate that wants to reason about what the filter did to a file has
        to ask the same question the same way.
        """
        stripped = text.lstrip()
        return filename.lower().endswith(".xml") or stripped.startswith("<")

    def detect(self, text: str) -> dict[str, int]:
        """Scan text for residual sensitive matches WITHOUT mutating it.

        Returns {category: match_count}. Used by the post-scan redaction
        verification gate; never returns raw values.
        """
        findings: dict[str, int] = {}

        def _bump(category: str, count: int = 1) -> None:
            if count:
                findings[category] = findings.get(category, 0) + count

        for pattern, repl in self._active_patterns:
            if pattern is self._LOBSTER_BASE64_RE:
                continue  # XML-only pattern; too noisy on serialized JSON
            cat = repl.strip("[]").lower() if repl.startswith("[") else "pattern"
            _bump(cat, len(pattern.findall(text)))
        # A pair whose value is already a placeholder is not a residual --
        # it is proof the filter ran. Counting it made every correctly
        # redacted `name="password" value="[PASSWORD_REDACTED]"` look like a
        # leak, which matters wherever a detection means "refuse to publish
        # this file".
        _bump("sensitive_kv", sum(
            1 for match in self._SENSITIVE_KV.finditer(text)
            if not _is_redaction_placeholder(text[match.end(1):match.start(2)])
        ))
        if self._level_includes(RedactionLevel.STANDARD):
            for m in self._URL_RE.finditer(text):
                host_match = self._URL_HOST_RE.match(m.group(0))
                if not (host_match and self._is_safe_domain(host_match.group(1))):
                    _bump("url")
            for m in self._FQDN_RE.finditer(text):
                if not self._is_safe_domain(m.group(0)):
                    _bump("fqdn")
            for m in self._UNC_HOST_RE.finditer(text):
                if not self._is_safe_domain(m.group(2)):
                    _bump("unc_host")
        _bump("internal_descriptor_token", len(self._DESCRIPTOR_TOKEN_RE.findall(text)))
        return findings

    # `url`/`fqdn`/`unc_host` findings that exist ONLY inside an xmlns
    # declaration are not leaks: `filter_text` deliberately preserves those
    # URIs because they are document structure (see `_XMLNS_DECL_RE`).
    # Credential-shaped findings are never excused this way -- a namespace
    # URI carrying `?password=` is a leak wherever it sits.
    _NAMESPACE_STRUCTURAL_CATEGORIES: frozenset[str] = frozenset({
        "url", "fqdn", "unc_host",
    })

    def detect_outside_namespaces(self, text: str) -> dict[str, int]:
        """`detect`, minus endpoint findings that live only in xmlns decls.

        Without this, every XML file declaring a project-specific namespace
        (`xmlns:tns="http://orders.acme.internal/schema"`) reports a
        residual URL and FQDN forever, because `filter_text` correctly left
        it alone.
        """
        findings = self.detect(text)
        if not findings:
            return findings
        masked, _ = self._mask_xmlns_decls(text)
        outside = self.detect(masked)
        return {
            category: count
            for category, count in findings.items()
            if category in outside
            or category not in self._NAMESPACE_STRUCTURAL_CATEGORIES
        }

    # `key = value` / `"key": "value"` in plain configuration text. The
    # filter's own key/value pattern is XML-attribute shaped
    # (`name="password" ... value="..."`) and its credential-parameter
    # pattern requires query-string context, so a plain
    # `datasource.password=hunter2` line in a .properties/.txt/.json file
    # passes BOTH untouched (verified). This detector closes that gap for
    # gates that copy such files; it never rewrites anything.
    _PLAIN_KV_RE = re.compile(
        r"""(?:^|[\s,{])["']?([A-Za-z_][\w.\-]{0,60})["']?\s*[:=]\s*["']?([^\s"',;}]+)""",
        re.MULTILINE,
    )

    def detect_key_value_secrets(self, text: str) -> dict[str, int]:
        """Count `sensitive_name = value` pairs in non-XML configuration text.

        Intended for text the filter's XML-shaped patterns do not cover.
        Applying it to XML/Java content would flag ordinary code such as
        `String password = decoded.substring(0, i)`, which the filter
        deliberately leaves intact.
        """
        count = 0
        for name, value in self._PLAIN_KV_RE.findall(text):
            if not value or _is_redaction_placeholder(value):
                continue
            if self.is_sensitive_var_name(name):
                count += 1
        return {"key_value_secret": count} if count else {}

    def detect_residual(self, text: str, filename: str = "") -> dict[str, int]:
        """Residual-secret findings for text about to be published as-is.

        Chooses the detectors that match what `filter_text` actually did to
        this content: XML keeps its namespace declarations (so those are
        excused), plain configuration text gets the extra key/value sweep
        the XML-shaped patterns cannot perform.
        """
        if self.is_xml_text(text, filename):
            findings = dict(self.detect_outside_namespaces(text))
            for category, count in self.detect_named_value_secrets(text).items():
                findings[category] = findings.get(category, 0) + count
            return findings
        findings = dict(self.detect(text))
        for category, count in self.detect_key_value_secrets(text).items():
            findings[category] = findings.get(category, 0) + count
        return findings

    # ── Name-semantics rule at text level ───────────────────────────
    #
    # `_SENSITIVE_KV` above implements this rule for a FIXED key list
    # (`name="password"`), while `post_filter` implements it for parsed
    # models with the token-aware `is_sensitive_var_name` matcher. The two
    # vocabularies had drifted, and a Talend context item is exactly where
    # that shows: `<contextParameter name="DbPassword" type="id_Password"
    # value="<plaintext>"/>` is redacted by the structural layer (which
    # sees the parsed ContextVariable) and NOT by the text layer -- so the
    # parsed scan is clean while the source file still holds the secret.
    # That is invisible as long as only parsed models are published; it is
    # a leak the moment raw file text is (see
    # `evidence_store.write_sanitized_workspace`).
    _XML_TAG_RE = re.compile(r"<[^<>]*>")
    _XML_ATTR_RE = re.compile(r'([A-Za-z_:][-\w:.]*)\s*=\s*"([^"]*)"')
    # Attributes that name the value carried by the same tag.
    _NAME_ATTRIBUTES: tuple[str, ...] = ("name", "key", "field", "label")
    # Attributes whose content IS the value.
    _VALUE_ATTRIBUTES: tuple[str, ...] = ("value", "defaultValue")
    _PASSWORD_TYPES: frozenset[str] = frozenset({"id_password", "password"})
    # Attributes whose NAME may look sensitive but whose content is a label,
    # an identifier or a type -- never the secret itself. `name="db_password"`
    # is the fact a reader needs; `Password="..."` on a connection element is
    # the secret. Compared on the local name (namespace prefix stripped).
    _STRUCTURAL_ATTRIBUTES: frozenset[str] = frozenset({
        "name", "key", "field", "label", "type", "id", "idref", "href",
        "elementref", "connector", "componentname", "componentversion",
        "displayname", "repositorycontextid", "version", "path",
    })

    @staticmethod
    def _attribute_local_name(attribute: str) -> str:
        return attribute.rsplit(":", 1)[-1]

    def _sensitive_value_attributes(self, attributes: dict[str, str]) -> list[str]:
        """Attribute names in one tag whose OWN name marks their value secret.

        The second shape of the name-semantics rule. The first shape is a
        `name="..."` attribute describing a sibling `value="..."`; this one is
        the attribute itself being the named value, as Talend serializes it
        on metadata connection elements (`Password="..."`, `ApiKey="..."`).
        """
        found: list[str] = []
        for attribute, value in attributes.items():
            local = self._attribute_local_name(attribute)
            if local.casefold() in self._STRUCTURAL_ATTRIBUTES:
                continue
            if not value or _is_redaction_placeholder(value):
                continue
            if self.is_sensitive_var_name(local):
                found.append(attribute)
        return found

    def _tag_is_sensitive(self, attributes: dict[str, str]) -> bool:
        if attributes.get("type", "").strip().casefold() in self._PASSWORD_TYPES:
            return True
        return any(
            self.is_sensitive_var_name(attributes[attribute])
            for attribute in self._NAME_ATTRIBUTES
            if attributes.get(attribute)
        )

    def redact_named_value_pairs(self, text: str) -> str:
        """Redact `value="..."` in any tag whose NAME says it is sensitive.

        The text-level counterpart of the structural name-semantics rule.
        Scoped to one tag at a time so a name in one element can never
        redact a value in another, and applied only to the attributes that
        carry a value -- the name itself is kept, because "there is a
        password here" is exactly the fact a reader needs.
        """
        def replace_tag(match: re.Match[str]) -> str:
            tag = match.group(0)
            attributes = dict(self._XML_ATTR_RE.findall(tag))
            # Shape 2: the attribute name is the secret's name.
            for attribute in self._sensitive_value_attributes(attributes):
                self._record_redaction("sensitive_attribute", attributes[attribute])
                tag = re.sub(
                    rf'(\b{re.escape(attribute)}\s*=\s*")[^"]*(")',
                    r"\1[REDACTED]\2",
                    tag,
                    count=1,
                )
            if not self._tag_is_sensitive(attributes):
                return tag
            # Shape 1: a name/type attribute marks the sibling value.
            for attribute in self._VALUE_ATTRIBUTES:
                current = attributes.get(attribute)
                if not current or _is_redaction_placeholder(current):
                    continue
                self._record_redaction("named_value_pair", current)
                tag = re.sub(
                    rf'({re.escape(attribute)}\s*=\s*")[^"]*(")',
                    r"\1[REDACTED]\2",
                    tag,
                    count=1,
                )
            return tag

        return self._XML_TAG_RE.sub(replace_tag, text)

    def detect_named_value_secrets(self, text: str) -> dict[str, int]:
        """Count sensitive name/value tags that still carry a real value.

        The verification half of `redact_named_value_pairs`: a gate that
        publishes raw text must fail closed on a shape the redaction pass
        did not recognize, rather than trusting that it handled everything.
        """
        count = 0
        attribute_count = 0
        for match in self._XML_TAG_RE.finditer(text):
            attributes = dict(self._XML_ATTR_RE.findall(match.group(0)))
            attribute_count += len(self._sensitive_value_attributes(attributes))
            if not self._tag_is_sensitive(attributes):
                continue
            count += sum(
                1
                for attribute in self._VALUE_ATTRIBUTES
                if attributes.get(attribute)
                and not _is_redaction_placeholder(attributes[attribute])
            )
        findings: dict[str, int] = {}
        if count:
            findings["named_value_secret"] = count
        if attribute_count:
            findings["sensitive_attribute_secret"] = attribute_count
        return findings

    def get_audit_report(self) -> dict[str, Any]:
        """Return audit data: category counts + hashes. Never raw values."""
        return {
            "redaction_level": self._level.value,
            "summary": {cat: len(hashes) for cat, hashes in sorted(self._audit.items())},
            "total_redactions": sum(len(h) for h in self._audit.values()),
            "details": {
                cat: {"count": len(hashes), "hashes": hashes}
                for cat, hashes in sorted(self._audit.items())
            },
        }

    def audit_checkpoint(self) -> dict[str, int]:
        """Capture audit offsets so a deterministic cache can store a delta."""
        return {category: len(hashes) for category, hashes in self._audit.items()}

    def audit_since(self, checkpoint: dict[str, int]) -> dict[str, list[str]]:
        """Return only redaction hashes recorded after ``checkpoint``."""
        return {
            category: list(hashes[checkpoint.get(category, 0):])
            for category, hashes in self._audit.items()
            if len(hashes) > checkpoint.get(category, 0)
        }

    def replay_audit(self, delta: dict[str, list[str]]) -> None:
        """Replay cached redaction audit evidence without handling raw values."""
        for category, hashes in delta.items():
            self._audit[category].extend(hashes)

    def reset_audit(self) -> None:
        """Clear the audit trail (e.g., between files)."""
        self._audit.clear()
