"""All Pydantic data models shared across platforms and passes."""

from __future__ import annotations

import warnings
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import ClassVar, Literal

from pydantic import BaseModel, Field, field_validator


# ── Redaction Descriptor ──────────────────────────────────────────────
#
# "Mask-and-CAPTURE" instead of "mask-and-DISCARD": whenever the scanner
# redacts a sensitive value (a URL, connection string, endpoint, etc.), this
# model captures ONLY provably-non-sensitive structural facts about the
# ORIGINAL value so downstream doc generation keeps some signal instead of
# losing it entirely to a bare placeholder like "[URL_REDACTED]".
#
# HARD invariant: every field here must be an enum/bool/known-scheme-token.
# Never a host, path, query string, username, or credential value. When a
# fact cannot be safely determined, the field is left None -- guessing is
# not acceptable (see intodoc.scanner.credential_filter.CredentialFilter
# .describe_value, the single place this model is constructed from raw
# text).


class RedactionDescriptor(BaseModel):
    """Safe, structural facts captured about a value before it was redacted."""

    # URI scheme token from a small fixed vocabulary, e.g. "https", "http",
    # "jdbc", "jms", "sftp", "smtp", "ldap", "amqp". Never an arbitrary
    # regex-captured prefix -- only recognized, known scheme tokens.
    scheme: str | None = None
    # Coarse connection/resource category, e.g. "db", "rest", "jms", "file",
    # "smtp", "directory".
    category: str | None = None
    # Whether the value carried any auth signal (userinfo, auth header,
    # password/token/secret param name). None means undeterminable.
    auth_present: bool | None = None
    # Auth mechanism TYPE only -- never the credential value itself.
    auth_type: Literal["none", "basic", "bearer", "api_key", "oauth", "unknown"] | None = None
    # TLS/SSL on-off flag, where determinable from scheme or an explicit
    # ssl/tls/encrypt=true|false flag.
    tls: bool | None = None
    # Whether a host/authority component was present. Never the host value.
    host_present: bool | None = None


# ── File Classification ──────────────────────────────────────────────


class FileType(str, Enum):
    JOB = "job"
    JOB_PROPERTIES = "job_properties"
    CONNECTION = "connection"
    CONTEXT = "context"
    ROUTINE = "routine"
    SCHEMA = "schema"
    JOBLET = "joblet"
    SQL_PATTERN = "sql_pattern"
    DOCUMENTATION = "documentation"
    CONFIG = "config"
    # Enterprise Talend artifact categories. Additive members; historic scan
    # JSON never carries them, and every existing member keeps its value.
    STRUCTURE = "structure"          # Structures/**/*.xml (TDM structure)
    XSLT = "xslt"                    # *.xsl / *.xslt (route/job transforms)
    TDM_MAP = "tdm_map"              # Maps/**/*.xml (TDM map)
    SERVICE = "service"              # services/*.item (SOAP service design)
    WSDL = "wsdl"                    # *.wsdl service contract
    NAMESPACE = "namespace"          # "Namespace Containers"/*.xml
    PROJECT = "project"              # talend.project descriptor
    RESOURCE = "resource"            # other files under resources/ route_resources/
    UNKNOWN = "unknown"


class ScannedFile(BaseModel):
    path: Path
    relative_path: str
    file_type: FileType
    sha256: str
    size_bytes: int
    platform_metadata: dict = Field(default_factory=dict)


# ── Parsed Job / Component Models ────────────────────────────────────


class ComponentParam(BaseModel):
    name: str
    value: str
    field_type: str = ""
    # Additive: a Talend TABLE-field parameter carries its payload in
    # <elementValue elementRef=.. value=..> children, not in `value` (which
    # is serialized empty). Each dict is one row keyed by elementRef, in
    # document order. Empty for every non-TABLE parameter.
    rows: list[dict[str, str]] = Field(default_factory=list)
    # Additive: populated only when `value` was redacted (see post_filter.py
    # ._filter_component_params). Captures structural facts about the
    # original value that the redaction placeholder alone would discard.
    redaction_descriptor: RedactionDescriptor | None = None

    @staticmethod
    def row_column_key(row: dict[str, str], role: str) -> str:
        """The key of one logical column of a TABLE row ("NAME"/"VALUE").

        Talend names table columns with elementRefs such as
        ``PARAM_NAME_COLUMN`` / ``PARAM_VALUE_COLUMN``. Positional order is
        the last resort so an unfamiliar table is still readable rather
        than silently empty. Defined here, on the model that owns `rows`,
        because the parser, the structural redaction layer and the
        verification gate must all agree on which cell names which -- a
        second copy of this rule is how a sensitive value slips past one of
        the three.
        """
        exact = f"PARAM_{role}_COLUMN"
        if exact in row:
            return exact
        for key in row:
            if key.upper().endswith(f"_{role}_COLUMN"):
                return key
        keys = list(row)
        index = 0 if role == "NAME" else 1
        return keys[index] if len(keys) > index else ""

    @classmethod
    def row_column(cls, row: dict[str, str], role: str) -> str:
        """The value of one logical column of a TABLE row."""
        return row.get(cls.row_column_key(row, role), "")


class ComponentSchemaColumn(BaseModel):
    """One <column> of a component <metadata> schema, verbatim.

    `dynamic` marks Talend's `id_Dynamic` column type: a dynamic column
    stands for an unknown number of real columns, so a schema containing
    one can never be treated as an enumerated field list (see
    `ComponentSchema.dynamic`).
    """
    name: str
    type: str = ""
    nullable: bool = True
    key: bool = False
    length: str = ""
    precision: str = ""
    default_value: str = ""
    pattern: str = ""
    comment: str = ""
    source_type: str = ""
    dynamic: bool = False


class ComponentSchema(BaseModel):
    """A component's row schema for one connector (FLOW, REJECT, custom).

    `declaration` records whether Talend stores the schema inline
    (`built_in`) or by reference to a repository schema
    (`repository`, with `repository_schema_ref` holding the metadata id);
    `unknown` means the export carried no SCHEMA*:SCHEMA_TYPE parameter
    that could be bound to this connector -- never guessed.
    """
    connector: str = ""
    name: str = ""
    columns: list[ComponentSchemaColumn] = Field(default_factory=list)
    dynamic: bool = False
    declaration: Literal["built_in", "repository", "unknown"] = "unknown"
    repository_schema_ref: str = ""


class Component(BaseModel):
    unique_name: str
    component_type: str  # e.g. "tMSSqlInput", "tMap", "tBigQueryOutput"
    params: list[ComponentParam] = Field(default_factory=list)
    # Custom code carried by this component (tJava/tJavaRow/tJavaFlex CODE
    # params, joined). Mirrors params[].CODE so downstream consumers doing
    # component.get("code") find it; params stay unchanged for back-compat.
    code: str | None = None
    incoming_connections: list[str] = Field(default_factory=list)
    outgoing_connections: list[str] = Field(default_factory=list)
    metadata_connection_ref: str = ""
    # Additive enterprise-fidelity fields. Defaults preserve historic JSON.
    schemas: list[ComponentSchema] = Field(default_factory=list)
    # Talend omits the ACTIVATE parameter on an active component and writes
    # ACTIVATE=false on a disabled one, so absence means active.
    active: bool = True
    # PROPERTY:PROPERTY_TYPE, lower-cased: "built_in" | "repository" | "".
    declaration: str = ""
    # PROPERTY:REPOSITORY_PROPERTY_TYPE verbatim (the repository metadata id).
    # `metadata_connection_ref` above holds the RESOLVED connection name.
    repository_property_ref: str = ""

    # Param names that carry executable custom code, in execution order.
    CODE_PARAM_NAMES: ClassVar[tuple[str, ...]] = (
        "CODE_START", "CODE", "CODE_MAIN", "CODE_END", "CODE_ONCE",
    )

    def compact_params(self) -> dict[str, str]:
        """Collapse [{name, value, field_type}] → {name: value} for LLM consumption."""
        return {p.name: p.value for p in self.params}

    def derive_code_from_params(self) -> str | None:
        """Join code-bearing param values (CODE, CODE_MAIN, ...) into one block."""
        by_name = {p.name: p.value for p in self.params if p.value}
        parts = [by_name[n] for n in self.CODE_PARAM_NAMES if n in by_name]
        return "\n".join(parts) if parts else None


class TMapEntry(BaseModel):
    table_name: str
    column_name: str
    expression: str


class TMapData(BaseModel):
    component_name: str = ""
    # Complete sanitized attributes retain lookup, filter/reject and schema
    # semantics even when a consumer does not yet interpret that capability.
    table_details: list[dict] = Field(default_factory=list)
    input_tables: list[str] = Field(default_factory=list)
    output_tables: list[str] = Field(default_factory=list)
    entries: list[TMapEntry] = Field(default_factory=list)
    var_entries: list[TMapEntry] = Field(default_factory=list)


class TXMLMapField(BaseModel):
    """One field node in a tXMLMap (TalendXMLMap) input or output tree."""
    name: str
    xpath: str = ""
    field_type: str = ""
    # Mapping formula, present on output-tree fields only (e.g.
    # "row7.GUIDElement" or "TalendDate.getDate(...)"). Already textually
    # names its upstream source field(s) -- no index resolution required to
    # read the lineage-relevant content.
    expression: str = ""
    loop: bool = False


class TXMLMapTree(BaseModel):
    name: str
    fields: list[TXMLMapField] = Field(default_factory=list)


class TXMLMapData(BaseModel):
    """Structural + expression capture for tXMLMap (TalendXMLMap) -- an
    XML-tree-shaped mapper distinct from classic tMap (``TMapData`` above).
    Talend stores it as a nested ``inputTrees``/``outputTrees`` XML tree
    (xpath-addressed) rather than flat table columns; ``fields`` flattens
    that tree depth-first, preserving each field's own xpath.

    Output field ``expression`` values already textually reference their
    upstream input field (see ``TXMLMapField``), so the lineage-relevant
    content is captured directly. The component's positional ``connections``
    list uses EMF proxy refs (e.g.
    ``//@node.2/@nodeData/@inputTrees.0/@nodes.1``) that Talend Studio uses
    to redraw the wiring diagram. Supported local references are resolved into
    typed pairs; every reference is retained verbatim and unsupported/cross-node
    forms remain explicit in ``unresolved_connections`` with a scan warning.
    """
    input_trees: list[TXMLMapTree] = Field(default_factory=list)
    output_trees: list[TXMLMapTree] = Field(default_factory=list)
    var_entries: list[TMapEntry] = Field(default_factory=list)
    raw_connections: list[str] = Field(default_factory=list)
    resolved_connections: list[dict[str, str]] = Field(default_factory=list)
    unresolved_connections: list[dict[str, str]] = Field(default_factory=list)
    # The tXMLMap component's Talend UNIQUE_NAME. This is known directly from
    # the enclosing node even when its XML-tree proxy wires cannot be resolved
    # into upstream/downstream components; it is safe L3/L4 runtime evidence.
    component_name: str = ""


class TRunJobRef(BaseModel):
    """A tRunJob parent -> child invocation.

    Resolution is IDENTITY-FIRST: the child is taken from
    `PROCESS:PROCESS_TYPE_PROCESS` (a repository GUID) resolved through the
    scanned `.properties` index, and only falls back to the `PROCESS`
    parameter -- a Studio label CACHE that goes stale when the child job is
    renamed. `reference_source` records which of the two produced
    `child_job`, so a consumer never has to guess.
    """
    child_job: str
    child_job_xmi_id: str = ""
    context_params: list[ComponentParam] = Field(default_factory=list)
    resolved_job_id: str = ""
    resolution: str = "unresolved"  # same_root | global | ambiguous | unresolved | dynamic
    # Additive tRunJob call semantics, verbatim from the component parameters.
    version: str = ""                              # PROCESS:PROCESS_TYPE_VERSION
    context_name: str = ""                         # PROCESS:PROCESS_TYPE_CONTEXT
    transmit_whole_context: bool | None = None     # TRANSMIT_WHOLE_CONTEXT
    transmit_original_context: bool | None = None  # TRANSMIT_ORIGINAL_CONTEXT
    die_on_child_error: bool | None = None         # DIE_ON_CHILD_ERROR
    # USE_DYNAMIC_JOB=true: the child is chosen at runtime, so no static
    # target exists and `resolution` stays "dynamic".
    dynamic_job: bool = False
    reference_source: Literal["identity", "label", "none"] = "none"
    # Repository path of the design the GUID resolved to (version stripped,
    # e.g. "process/Orders/Orders_Load"). Breaks same-name ambiguity inside
    # one root; empty when resolution was not identity-based.
    target_item_path: str = ""


class ArtifactReference(BaseModel):
    """A typed reference between independently executable Talend designs.

    ``jobs`` remains the wire-format collection for historic callers, but a
    Talend Route is not a DI Job.  This model keeps the relation explicit
    without making consumers infer it from a component palette prefix.
    """
    target_name: str
    target_xmi_id: str = ""
    relation_type: str  # job_calls_job | route_invokes_job | job_uses_joblet
    component_name: str = ""
    resolved_artifact_id: str = ""
    resolution: str = "unresolved"  # same_root | global | ambiguous | unresolved
    # Additive cTalendJob invocation semantics (see TRunJobRef for the
    # identity-first rule; `reference_source` has the same meaning here).
    version: str = ""            # SELECTED_JOB_NAME:PROCESS_TYPE_VERSION
    context_name: str = ""       # SELECTED_JOB_NAME:PROCESS_TYPE_CONTEXT
    use_route_context: bool | None = None  # USE_ROUTE_CONTEXT
    reference_source: Literal["identity", "label", "none"] = "none"
    context_params: list[ComponentParam] = Field(default_factory=list)
    target_item_path: str = ""


class Connection(BaseModel):
    name: str
    source: str
    target: str
    connector_name: str = ""
    line_style: int = 0  # 0=row, 1=trigger, etc.
    # Same ACTIVATE convention as Component.active: absent means active.
    active: bool = True


class ContextVariable(BaseModel):
    name: str
    type: str = "String"
    values: dict[str, str] = Field(default_factory=dict)  # env_name → value
    # Talend repository context reference carried by inline job contexts.
    # This is a stable project artifact ID, not a folder/name heuristic.
    repository_context_id: str = ""
    # Additive: env_name -> descriptor, populated only for envs whose value
    # was redacted (see post_filter.py._filter_context_variable).
    redaction_descriptors: dict[str, RedactionDescriptor] = Field(default_factory=dict)


class ContextGroup(BaseModel):
    name: str
    variables: list[ContextVariable] = Field(default_factory=list)
    # Canonical identity and provenance for contexts parsed from a Talend
    # project.  Defaults keep historic scan JSON fully compatible.
    context_id: str = ""
    context_key: str = ""
    source_root: str = ""
    source_project: str = ""
    source_role: str = ""
    purpose: str = ""
    description: str = ""


class ParsedJob(BaseModel):
    name: str
    # Stable identity for composite source bundles.  Empty for historic scan
    # results; for a normal one-root project it is equal to ``name``.
    job_id: str = ""
    source_root: str = ""
    source_design: str = ""  # Talend process | routes; needed for same-path collisions
    path: str
    purpose: str = ""
    author: str = ""
    version: str = ""
    creation_date: str = ""
    modification_date: str = ""
    components: list[Component] = Field(default_factory=list)
    connections: list[Connection] = Field(default_factory=list)
    context_groups: list[ContextGroup] = Field(default_factory=list)
    tmap_data: list[TMapData] = Field(default_factory=list)
    txmlmap_data: list[TXMLMapData] = Field(default_factory=list)
    trunjob_refs: list[TRunJobRef] = Field(default_factory=list)
    artifact_refs: list[ArtifactReference] = Field(default_factory=list)
    raw_routines: list[str] = Field(default_factory=list)
    group: str = ""
    subgroup: str = ""
    active: bool = True
    # Additive Camel palette evidence. Canonical Job/Route identity comes from
    # the Talend repository directory and is stored in artifact_kind below.
    is_esb_route: bool = False
    esb_component_types: list[str] = Field(default_factory=list)
    # Canonical Talend repository taxonomy.  Defaults preserve historic scan
    # JSON; the parser assigns this from process/ versus routes/, never from
    # a c-component heuristic.
    artifact_kind: str = "job"  # job | route | joblet | routelet
    artifact_role: str = "standalone"  # standalone | reusable | routelet_wrapper
    scan_quality: str = "complete"  # complete | empty | parse_warning


class MetadataConnection(BaseModel):
    xmi_id: str
    name: str
    connection_type: str  # e.g. "MSSQL", "BigQuery", "File"
    host: str = ""
    port: str = ""
    database: str = ""
    schema_name: str = ""
    file_path: str = ""
    additional_params: dict = Field(default_factory=dict)
    # Additive: populated when `host` was redacted (see
    # post_filter.py._filter_metadata_connection).
    host_redaction: RedactionDescriptor | None = None
    # Additive: key -> descriptor, populated only for additional_params
    # entries whose value was rewritten by the text-level catch-all filter.
    additional_params_redactions: dict[str, RedactionDescriptor] = Field(default_factory=dict)


# ── Routine ──────────────────────────────────────────────────────────


class Routine(BaseModel):
    name: str
    source_code: str = ""
    is_system: bool = False
    routine_id: str = ""
    source_root: str = ""
    path: str = ""
    version: str = ""
    property_id: str = ""
    # Historical payloads may contain the old 200-line preview.
    source_complete: bool = False
    source_sha256: str = ""
    method_resolution: str = "whole_source_only"


# ── Project Manifest ─────────────────────────────────────────────────


class ProjectManifest(BaseModel):
    job_calls: dict[str, list[str]] = Field(default_factory=dict)
    job_called_by: dict[str, list[str]] = Field(default_factory=dict)
    job_connections_used: dict[str, list[str]] = Field(default_factory=dict)
    connection_used_by: dict[str, list[str]] = Field(default_factory=dict)
    job_contexts_used: dict[str, list[str]] = Field(default_factory=dict)
    routines_used_by: dict[str, list[str]] = Field(default_factory=dict)
    routine_metadata: dict[str, dict] = Field(default_factory=dict)
    job_routine_links: dict[str, list[dict[str, str]]] = Field(default_factory=dict)
    unresolved_routine_refs: dict[str, list[dict]] = Field(default_factory=dict)
    artifact_versions: list[dict[str, str]] = Field(default_factory=list)
    evidence_package: dict[str, str] = Field(default_factory=dict)
    job_groups: dict[str, str] = Field(default_factory=dict)
    job_external_systems: dict[str, list[str]] = Field(default_factory=dict)
    # Additive composite-bundle metadata.  Existing consumers can keep using
    # job_groups and the name-keyed maps above.
    source_roots: list[dict[str, str]] = Field(default_factory=list)
    job_source_roots: dict[str, str] = Field(default_factory=dict)
    job_files: dict[str, str] = Field(default_factory=dict)
    unresolved_job_calls: dict[str, list[dict[str, str]]] = Field(default_factory=dict)
    # Support-artifact lineage. Context keys are canonical within the combined
    # scan and resolve to stable Talend Property IDs where available.
    context_used_by: dict[str, list[str]] = Field(default_factory=dict)
    context_metadata: dict[str, dict] = Field(default_factory=dict)
    job_context_links: dict[str, list[dict[str, str]]] = Field(default_factory=dict)
    unresolved_context_refs: dict[str, list[dict[str, str]]] = Field(default_factory=dict)
    job_support_roots: dict[str, list[str]] = Field(default_factory=dict)
    # Additive typed topology facts.  Legacy job_* maps intentionally stay so
    # external clients can migrate independently.
    artifact_kinds: dict[str, str] = Field(default_factory=dict)
    artifact_relations: list[dict] = Field(default_factory=list)
    artifact_channels: list[dict] = Field(default_factory=list)
    artifact_endpoints: list[dict] = Field(default_factory=list)
    artifact_resources: list[dict] = Field(default_factory=list)
    # Pointer to scan/sanitized/manifest.json: the sanitized mirror of every
    # textual source file the walker inventoried. Keys: path, sha256,
    # file_count, capability_version (all strings, as evidence_package above).
    sanitized_workspace: dict[str, str] = Field(default_factory=dict)
    # Component/map -> support-artifact references (structure, xslt, tdm,
    # service) with resolution "exact" | "unresolved". Exact-token matching
    # only; a reference is never attributed by name similarity.
    resource_refs: list[dict] = Field(default_factory=list)


# ── Talend Data Mapper (TDM) Maps ───────────────────────────────────
#
# A THIRD, separate Talend mapping format (distinct from tMap and tXMLMap
# above), used by ESB/API Services projects to define request/response
# transformations as standalone `Maps/*.xml` artifacts rather than an inline
# job component.


class TdmMapField(BaseModel):
    """One flattened field in a TDM input or output map tree."""
    name: str
    path: str = ""  # dotted ancestor path within the tree, e.g. "KTA/Attributes/GUID"
    # Mapping formula, present on output-tree fields only. Already a
    # human-readable path reference into the input tree (e.g.
    # "in$/KTA/WID/Attributes/WID") -- no positional index resolution
    # needed, unlike TXMLMapData.raw_connections.
    expression: str = ""


class TdmMapTree(BaseModel):
    name: str
    fields: list[TdmMapField] = Field(default_factory=list)
    truncated: bool = False  # True when the field cap was hit (see ScanWarning)


class TdmMap(BaseModel):
    """A Talend Data Mapper (TDM) map definition from ``Maps/*.xml``.

    Talend Studio exports these under ``Maps/Jobs/<job_name>/`` or
    ``Maps/Routes/<route_name>/`` when the map is scoped to one artifact;
    ``owning_artifact``/``association`` reflect that directory convention.
    Maps directly under ``Maps/`` (no Jobs/Routes subfolder) carry no
    reliable ownership signal in the export and are reported unresolved --
    never guessed from name similarity.
    """
    name: str = ""
    path: str = ""  # relative path under the owning Talend root
    source_root: str = ""
    input_struct: str = ""
    output_struct: str = ""
    owning_artifact: str = ""  # resolved job_id/name, when association succeeds
    association: str = "unresolved"  # directory_jobs | directory_routes | unresolved
    input_tree: TdmMapTree | None = None
    output_tree: TdmMapTree | None = None


# ── TDM Structures (Structures/**/*.xml) ─────────────────────────────
#
# A Structure is the schema half of Talend Data Mapper: TDM maps
# (``TdmMap`` above) reference structures by name for their input and
# output trees. Structures live in their own repository directory with a
# ``.properties`` sidecar, so they are independently versioned artifacts,
# not part of any one job.


class StructureElement(BaseModel):
    """One element of a TDM structure, qualified by its path in the tree.

    Every attribute is copied verbatim from the export. `nullable` is
    `None` when the export did not state it -- absence is never read as
    "nullable=true".
    """
    name: str
    path: str
    data_type: str = ""
    occur_max_times: str = ""
    min_size: str = ""
    max_size: str = ""
    nullable: bool | None = None
    group_type: str = ""


class StructureDefinition(BaseModel):
    """A parsed ``Structures/**/*.xml`` structure definition.

    `parse_outcome` is `partial` when the file contained element tags this
    parser does not model (they are listed in `unmatched_tags`, never
    dropped silently) and `unsupported` when the file could not be parsed
    as XML at all. A structure is never omitted from the scan because of
    either.
    """
    name: str
    path: str
    source_root: str = ""
    property_id: str = ""
    version: str = ""
    root_element: str = ""
    elements: list[StructureElement] = Field(default_factory=list)
    element_count: int = 0
    parse_outcome: Literal["parsed", "partial", "unsupported"] = "parsed"
    unmatched_tags: list[str] = Field(default_factory=list)


# ── XSLT Transforms (*.xsl / *.xslt) ────────────────────────────────
#
# Talend routes and jobs delegate transformation to XSLT stylesheets held
# under ``route_resources/`` or ``resources/`` and referenced from a
# component parameter (cXSLT RESOURCE_URI, tXSLT XSLT_FILE, ...). The
# mapping logic is therefore invisible to any scan that only reads job
# items.

_XSLT_INSTRUCTIONS = (
    "value-of", "copy-of", "copy", "for-each", "apply-templates", "if",
    "when", "otherwise", "attribute", "element", "literal-element", "text",
    "call-template",
)


class XsltMapping(BaseModel):
    """One value-producing XSLT instruction inside a template.

    `instruction` is a closed vocabulary; anything else the stylesheet
    contains is recorded in `XsltTransform.unmatched_instructions` rather
    than being coerced into one of these names. `literal-element` is a
    non-XSL result element (literal output markup).
    """
    template_match: str = ""
    instruction: Literal[
        "value-of", "copy-of", "copy", "for-each", "apply-templates", "if",
        "when", "otherwise", "attribute", "element", "literal-element",
        "text", "call-template",
    ]
    select: str = ""
    test: str = ""
    output_path: str = ""
    mode: str = ""


class XsltTemplate(BaseModel):
    match: str = ""
    name: str = ""
    mode: str = ""


class XsltTransform(BaseModel):
    """A parsed XSLT stylesheet plus the components that reference it.

    `referenced_by` holds ``job_id::component_unique_name`` for every
    component whose parameters name this exact file (full repository path
    or file name). Matching is exact-token only: a stylesheet is never
    attributed to a component by name similarity.
    """
    name: str
    path: str
    source_root: str = ""
    templates: list[XsltTemplate] = Field(default_factory=list)
    mappings: list[XsltMapping] = Field(default_factory=list)
    variables: list[dict[str, str]] = Field(default_factory=list)
    params: list[dict[str, str]] = Field(default_factory=list)
    includes: list[str] = Field(default_factory=list)
    parse_outcome: Literal["parsed", "partial", "unsupported"] = "parsed"
    unmatched_instructions: list[str] = Field(default_factory=list)
    referenced_by: list[str] = Field(default_factory=list)


# ── SOAP Service Definitions (services/*.item + *.wsdl) ─────────────


class ServiceOperation(BaseModel):
    port_type: str = ""
    operation: str
    input_message: str = ""
    output_message: str = ""


class ServiceDefinition(BaseModel):
    """A Talend ESB service design and the operations it publishes.

    Only port type / operation / message NAMES are captured: a WSDL also
    carries endpoint addresses, which are connection evidence handled by
    the redaction layers, not service-contract structure.
    """
    name: str
    path: str
    source_root: str = ""
    property_id: str = ""
    version: str = ""
    wsdl_path: str = ""
    operations: list[ServiceOperation] = Field(default_factory=list)
    parse_outcome: Literal["parsed", "partial", "unsupported"] = "parsed"


# ── Mapping Accounting (deterministic, no LLM) ───────────────────────
#
# "How many fields did this mapper receive, how many did it write, and
# where did each written field come from" -- answered per mapper component
# so a reader can see coverage instead of inferring it from a sample of
# expressions. Every list is complete; nothing here is truncated.


class MappingRow(BaseModel):
    """One written output field and the provenance of its expression."""
    output_table: str
    output_field: str
    expression: str = ""
    classification: Literal[
        "direct_map", "expression", "constant", "lookup", "dynamic", "unresolved",
    ]
    # "table.column" (tMap) or tree path (tXMLMap/TDM/XSLT) references that
    # resolved to a declared input of this mapper, Var chains followed.
    source_refs: list[str] = Field(default_factory=list)
    # References that did not resolve to a declared input: runtime lookups
    # (context.*, globalMap, routine calls) and genuinely unknown identifiers.
    dynamic_refs: list[str] = Field(default_factory=list)


class MappingAccounting(BaseModel):
    """Field-level coverage for one mapper component.

    Invariant: ``mapped_from_input + constant_or_generated + lookup_derived
    + dynamic_unresolved == written_fields == len(rows)``.

    `offered_enumerable` is False when at least one input schema cannot be
    enumerated -- an ``id_Dynamic`` column stands for an unknown number of
    real columns, so `offered_fields` is a LOWER BOUND in that case and
    `unwritten_offered` cannot be complete. The unenumerable inputs are
    named in `unenumerable_inputs`.
    """
    unit_id: str = ""
    component_name: str = ""
    mapper_kind: Literal["tmap", "txmlmap", "tdm", "xslt"]
    offered_fields: int = 0
    offered_enumerable: bool = True
    unenumerable_inputs: list[str] = Field(default_factory=list)
    written_fields: int = 0
    mapped_from_input: int = 0
    constant_or_generated: int = 0
    lookup_derived: int = 0
    dynamic_unresolved: int = 0
    unwritten_offered: list[str] = Field(default_factory=list)
    lookup_tables: list[dict[str, str]] = Field(default_factory=list)
    filters: list[str] = Field(default_factory=list)
    reject_outputs: list[str] = Field(default_factory=list)
    rows: list[MappingRow] = Field(default_factory=list)
    # sha256("unit_id|component_name|mapper_kind")[:16] -- a stable join key
    # for consumers that page over `rows`.
    table_id: str = ""


# ── Capability Ledger (deterministic, no LLM) ────────────────────────


# `construct` is the published JSON key of this row (the ledger is a
# cross-service contract), and it collides with pydantic's deprecated
# `BaseModel.construct` classmethod, which makes pydantic emit a shadowing
# UserWarning at class-creation time. Renaming the field would break the
# contract; aliasing it would make `model_dump()` emit the wrong key. The
# suppression is scoped to this one class definition and to that one
# message -- no global warning filter, no behaviour change.
with warnings.catch_warnings():
    warnings.filterwarnings("ignore", message=r'Field name "construct".*', category=UserWarning)

    class CapabilityCount(BaseModel):
        """One (category, construct, status) tally derived from the scan.

        `status` is about SCANNER capability, not code quality:
        `supported` means the construct was fully modelled, `partial`
        means modelled with a stated gap, `dynamic` means it is resolved
        at runtime and therefore has no static answer, `unresolved` means
        a reference that could not be bound, `unsupported` means the
        scanner has no model for it at all.
        """
        category: str
        construct: str
        status: Literal[
            "supported", "partial", "dynamic", "unsupported", "unresolved",
        ]
        count: int = 0
        note: str = ""


class CapabilityLedger(BaseModel):
    """What this scan saw, and what it could not model, in one table.

    `file_outcomes` tallies `ScanResult.source_inventory` by outcome, so
    its values always sum to the number of walked inventory rows: every
    file is accounted for.
    """
    capability_version: str = "talend-capability-2"
    file_outcomes: dict[str, int] = Field(default_factory=dict)
    constructs: list[CapabilityCount] = Field(default_factory=list)


# ── Scan Result ──────────────────────────────────────────────────────


class ScanWarning(BaseModel):
    """Non-fatal issue captured during scanning (e.g. a single malformed
    file that was dropped from the scan). Surfaces silently-swallowed
    parser errors so the dashboard can show "X files failed to parse"
    instead of just a lower job count."""
    kind: str  # "parse_error" | "missing_file" | "unknown"
    file: str = ""  # relative path of the offending file, when known
    message: str
    phase: str = ""  # e.g. "metadata_index" | "job_id_index" | "context" | "job" | "recipe" | "function" | "profile" | "connection"


class ScanResult(BaseModel):
    platform: str
    repo_root: str
    scanned_at: datetime = Field(default_factory=datetime.now)
    files: list[ScannedFile] = Field(default_factory=list)
    jobs: list[ParsedJob] = Field(default_factory=list)
    metadata_connections: list[MetadataConnection] = Field(default_factory=list)
    context_groups: list[ContextGroup] = Field(default_factory=list)
    routines: list[Routine] = Field(default_factory=list)
    manifest: ProjectManifest = Field(default_factory=ProjectManifest)
    tdm_maps: list[TdmMap] = Field(default_factory=list)
    # Additive enterprise-artifact collections. Defaults keep every historic
    # scan_result.json loadable.
    structures: list[StructureDefinition] = Field(default_factory=list)
    xslt_transforms: list[XsltTransform] = Field(default_factory=list)
    services: list[ServiceDefinition] = Field(default_factory=list)
    mapping_accounting: list[MappingAccounting] = Field(default_factory=list)
    capability_ledger: CapabilityLedger | None = None
    schema_definitions: list[dict] = Field(default_factory=list)
    stats: dict = Field(default_factory=dict)
    warnings: list[ScanWarning] = Field(default_factory=list)
    source_inventory: list[dict[str, str]] = Field(default_factory=list)

    @field_validator("routines", mode="before")
    @classmethod
    def _coerce_routines(cls, v: list) -> list:
        """Backward compat: convert plain strings to Routine objects."""
        if v and isinstance(v[0], str):
            return [Routine(name=s) for s in v]
        return v


# ── Analysis Chunk ───────────────────────────────────────────────────


class AnalysisChunk(BaseModel):
    chunk_id: str
    group: str = ""
    jobs: list[ParsedJob] = Field(default_factory=list)
    related_connections: list[MetadataConnection] = Field(default_factory=list)
    related_contexts: list[ContextGroup] = Field(default_factory=list)
    related_routines: list[Routine] = Field(default_factory=list)
    manifest: ProjectManifest | None = None
    token_estimate: int = 0
    sha256: str = ""


# ── Pass Results ─────────────────────────────────────────────────────


class PassResult(BaseModel):
    pass_number: int
    pass_name: str
    chunk_id: str
    model_used: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    data: dict = Field(default_factory=dict)


# ── Component Inventory (Pass 1) ────────────────────────────────────


class InventoryComponent(BaseModel):
    name: str
    component_type: str
    location: str
    dependencies: list[str] = Field(default_factory=list)
    referenced_by: list[str] = Field(default_factory=list)
    description: str = ""


class ComponentInventory(BaseModel):
    components: list[InventoryComponent] = Field(default_factory=list)
    dependency_graph_mermaid: str = ""
    orphaned_components: list[str] = Field(default_factory=list)
    missing_references: list[str] = Field(default_factory=list)


# ── Execution Logic (Pass 2) ────────────────────────────────────────


class ExecutionStep(BaseModel):
    job_name: str
    trigger: str = ""
    control_flow: str = ""
    flowchart_mermaid: str = ""
    notes: str = ""


class ExecutionLogic(BaseModel):
    steps: list[ExecutionStep] = Field(default_factory=list)
    orchestration_mermaid: str = ""


# ── Data Flows (Pass 3) ─────────────────────────────────────────────


class DataInput(BaseModel):
    source_system: str
    source_table: str = ""
    source_query: str = ""
    columns: list[str] = Field(default_factory=list)


class Transformation(BaseModel):
    component: str
    expression: str
    human_explanation: str


class DataOutput(BaseModel):
    target_system: str
    target_table: str = ""
    write_mode: str = ""  # insert, upsert, truncate+load, etc.
    columns: list[str] = Field(default_factory=list)


class JobDataFlow(BaseModel):
    job_name: str
    inputs: list[DataInput] = Field(default_factory=list)
    transformations: list[Transformation] = Field(default_factory=list)
    outputs: list[DataOutput] = Field(default_factory=list)
    data_lineage_mermaid: str = ""


class DataFlows(BaseModel):
    flows: list[JobDataFlow] = Field(default_factory=list)
    cross_job_lineage_mermaid: str = ""


# ── Environment & Config (Pass 4) ───────────────────────────────────


class EnvComparison(BaseModel):
    variable_name: str
    values_by_env: dict[str, str] = Field(default_factory=dict)
    risk_notes: str = ""


class EnvironmentConfig(BaseModel):
    environments: list[str] = Field(default_factory=list)
    comparisons: list[EnvComparison] = Field(default_factory=list)
    prod_risks: list[str] = Field(default_factory=list)


# ── External Systems (Pass 5) ───────────────────────────────────────


class ExternalSystem(BaseModel):
    name: str
    system_type: str  # database, API, file system, cloud storage, etc.
    connection_details: str = ""
    used_by_jobs: list[str] = Field(default_factory=list)
    criticality: str = "medium"  # low, medium, high, critical


class ExternalSystems(BaseModel):
    systems: list[ExternalSystem] = Field(default_factory=list)
    topology_mermaid: str = ""


# ── Error Handling (Pass 6) ──────────────────────────────────────────


class JobErrorHandling(BaseModel):
    job_name: str
    rating: str  # good, adequate, poor, none
    error_components: list[str] = Field(default_factory=list)
    silent_failure_risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ErrorHandling(BaseModel):
    jobs: list[JobErrorHandling] = Field(default_factory=list)
    overall_rating: str = ""
    critical_gaps: list[str] = Field(default_factory=list)


# ── State & Side Effects (Pass 7) ───────────────────────────────────


class SideEffect(BaseModel):
    job_name: str
    effect_type: str  # temp file, staging table, global var, etc.
    description: str
    cleanup_exists: bool = False
    risk: str = ""


class StateSideEffects(BaseModel):
    effects: list[SideEffect] = Field(default_factory=list)
    cleanup_gaps: list[str] = Field(default_factory=list)


# ── Custom Code (Pass 8) ────────────────────────────────────────────


class CodeSnippet(BaseModel):
    location: str
    language: str = "java"
    code: str
    purpose: str
    hidden_business_rules: list[str] = Field(default_factory=list)


class CustomCode(BaseModel):
    snippets: list[CodeSnippet] = Field(default_factory=list)
    routines_summary: list[str] = Field(default_factory=list)


# ── Business Logic (Pass 9) ─────────────────────────────────────────


class BusinessRule(BaseModel):
    rule_id: str
    domain: str  # e.g. "vaccination scheduling", "inventory", "billing"
    description: str
    implemented_in: list[str] = Field(default_factory=list)
    impact_if_wrong: str = ""


class BusinessLogic(BaseModel):
    domains: list[str] = Field(default_factory=list)
    rules: list[BusinessRule] = Field(default_factory=list)


# ── Synthesis (Pass 10) ─────────────────────────────────────────────


class FAQItem(BaseModel):
    question: str
    answer: str


class RiskItem(BaseModel):
    category: str
    description: str
    severity: str  # low, medium, high, critical
    affected_components: list[str] = Field(default_factory=list)


class GlossaryItem(BaseModel):
    term: str
    definition: str


class Synthesis(BaseModel):
    executive_summary: str = ""
    faq: list[FAQItem] = Field(default_factory=list)
    glossary: list[GlossaryItem] = Field(default_factory=list)
    onboarding_guide: str = ""
    risk_dashboard: list[RiskItem] = Field(default_factory=list)
    key_findings: list[str] = Field(default_factory=list)


# ── Schema & Data Dictionary (Pass 11) ─────────────────────────────


class ColumnDefinition(BaseModel):
    table_name: str
    column_name: str
    data_type: str = ""
    length: str = ""
    nullable: bool = True
    is_pk: bool = False
    is_fk: bool = False
    fk_references: str = ""
    description: str = ""


class TableSchema(BaseModel):
    table_name: str
    source_system: str = ""
    columns: list[ColumnDefinition] = Field(default_factory=list)
    used_by_jobs: list[str] = Field(default_factory=list)


class SchemaDict(BaseModel):
    tables: list[TableSchema] = Field(default_factory=list)
    unmapped_columns: list[str] = Field(default_factory=list)
    schema_diagram_mermaid: str = ""


# ── Data Quality & Validation (Pass 12) ───────────────────────────


class ValidationRule(BaseModel):
    rule_id: str
    job_name: str
    component: str
    rule_type: str  # null_check, type_check, range_check, business_constraint, format_check
    description: str
    expression: str = ""
    severity: str = "medium"  # low, medium, high, critical


class DataQuality(BaseModel):
    rules: list[ValidationRule] = Field(default_factory=list)
    null_handling_patterns: list[str] = Field(default_factory=list)
    type_coercion_risks: list[str] = Field(default_factory=list)
    overall_quality_score: str = ""  # good, adequate, poor
    recommendations: list[str] = Field(default_factory=list)


# ── Naming Conventions (Pass 13) ──────────────────────────────────


class NamingViolation(BaseModel):
    entity_name: str
    entity_type: str  # job, component, connection, context_var
    expected_pattern: str
    actual_pattern: str
    severity: str = "low"


class NamingConventions(BaseModel):
    detected_patterns: list[str] = Field(default_factory=list)
    region_code_usage: dict[str, str] = Field(default_factory=dict)
    subsidiary_code_usage: dict[str, str] = Field(default_factory=dict)
    layer_code_usage: dict[str, str] = Field(default_factory=dict)
    violations: list[NamingViolation] = Field(default_factory=list)
    consistency_score: str = ""  # excellent, good, inconsistent, poor
    recommendations: list[str] = Field(default_factory=list)


# ── Scheduling & SLA (Pass 14) ────────────────────────────────────


class JobSchedule(BaseModel):
    job_name: str
    estimated_frequency: str = ""  # daily, hourly, on-demand, etc.
    dependency_chain: list[str] = Field(default_factory=list)
    chain_depth: int = 0
    estimated_duration: str = ""
    sla_recommendation: str = ""


class SchedulingSLA(BaseModel):
    schedules: list[JobSchedule] = Field(default_factory=list)
    critical_path: list[str] = Field(default_factory=list)
    execution_windows: list[str] = Field(default_factory=list)
    bottleneck_jobs: list[str] = Field(default_factory=list)
    dependency_diagram_mermaid: str = ""
    recommendations: list[str] = Field(default_factory=list)


# ── Security & Access Control (Pass 15) ───────────────────────────


class SecurityFinding(BaseModel):
    finding_id: str
    category: str  # credential_exposure, pii_detected, access_pattern, encryption, hardcoded_secret
    severity: str  # low, medium, high, critical
    location: str
    description: str
    remediation: str = ""


class SecurityAccess(BaseModel):
    findings: list[SecurityFinding] = Field(default_factory=list)
    credential_management: str = ""  # description of how credentials are managed
    pii_columns: list[str] = Field(default_factory=list)
    data_classification: dict[str, str] = Field(default_factory=dict)  # table → classification level
    encryption_usage: list[str] = Field(default_factory=list)
    overall_security_rating: str = ""  # good, adequate, poor, critical
    recommendations: list[str] = Field(default_factory=list)


# ── Performance Profile (Pass 16) ─────────────────────────────────


class JobPerformance(BaseModel):
    job_name: str
    estimated_row_count: str = ""
    heavy_operations: list[str] = Field(default_factory=list)
    batch_sizes: dict[str, str] = Field(default_factory=dict)  # component → batch size
    parallel_execution: bool = False
    performance_risks: list[str] = Field(default_factory=list)
    optimization_opportunities: list[str] = Field(default_factory=list)


class PerformanceProfile(BaseModel):
    jobs: list[JobPerformance] = Field(default_factory=list)
    slow_job_candidates: list[str] = Field(default_factory=list)
    memory_intensive_jobs: list[str] = Field(default_factory=list)
    overall_performance_rating: str = ""
    recommendations: list[str] = Field(default_factory=list)


# ── Cross-Region Analysis (Pass 17) ───────────────────────────────


class RegionPattern(BaseModel):
    region: str
    job_count: int = 0
    components_used: list[str] = Field(default_factory=list)
    unique_patterns: list[str] = Field(default_factory=list)
    deviations_from_standard: list[str] = Field(default_factory=list)


class CrossRegion(BaseModel):
    regions: list[RegionPattern] = Field(default_factory=list)
    shared_patterns: list[str] = Field(default_factory=list)
    standardization_score: str = ""  # high, medium, low
    region_comparison_mermaid: str = ""
    recommendations: list[str] = Field(default_factory=list)


# ── Reusability & Refactoring (Pass 18) ───────────────────────────


class DuplicateLogic(BaseModel):
    description: str
    locations: list[str] = Field(default_factory=list)
    lines_duplicated: int = 0
    refactoring_suggestion: str = ""


class Reusability(BaseModel):
    duplicated_logic: list[DuplicateLogic] = Field(default_factory=list)
    shared_components: list[str] = Field(default_factory=list)
    joblet_usage: list[str] = Field(default_factory=list)
    code_smells: list[str] = Field(default_factory=list)
    reusability_score: str = ""  # excellent, good, poor
    refactoring_roadmap: list[str] = Field(default_factory=list)


# ── Migration Complexity Assessment (Pass 19) ─────────────────────


class MigrationBlocker(BaseModel):
    blocker: str = ""
    severity: str = ""  # "critical", "high", "medium", "low"
    component: str = ""
    recommendation: str = ""


class JobMigrationAssessment(BaseModel):
    job_name: str = ""
    complexity: str = ""  # "simple", "medium", "complex", "manual"
    auto_migrate_probability: float = 0.0  # 0.0-1.0
    effort_estimate_hours: float = 0.0
    blockers: list[MigrationBlocker] = Field(default_factory=list)
    source_components: int = 0
    transform_components: int = 0
    custom_code_components: int = 0
    tmap_expression_count: int = 0
    rationale: str = ""


class MigrationAssessment(BaseModel):
    """Pass 19 result: per-job migration complexity scoring."""
    assessments: list[JobMigrationAssessment] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)


# ── Column-Level Lineage (Pass 20, extended by the S4 deterministic pass) ──
#
# Originally populated by the abandoned 21-pass LLM analyzer (dead code --
# nothing referenced these models until the S4 lineage pass, see
# RAG_pipeline/docs/topology-lineage-runtime-architecture.md sec 2.2/D5).
# `intodoc/src/intodoc/lineage.py` now populates these deterministically from
# tMap, tXMLMap and associated TDM map expressions; no LLM involved.


class LineageConfidence(str, Enum):
    """How much to trust a lineage edge, in decreasing order of trust.

    CERTAIN  -- a clean, single, statically-resolved reference end to end.
    LIKELY   -- statically resolved but via a multi-ref expression, a lookup
                join, or a mix of resolved and dynamic references.
    DYNAMIC  -- no static reference could be resolved (globalMap/context/
                routine calls only); never fabricated as if it were known.
    OPAQUE   -- reserved for components/artifacts that carry no safely
                resolvable structured mapping expression (e.g. tJavaRow or
                a partially parsed mapper); never used to fabricate lineage.
    INFERRED -- a job-boundary edge stitched by the S5 cross-job pass from
                circumstantial evidence (trunjob context-param passing, or
                output/input table identity) rather than a parsed
                expression; always distinct from the S4 intra-job tiers
                above, never claimed to be CERTAIN/LIKELY.
    """

    CERTAIN = "certain"
    LIKELY = "likely"
    DYNAMIC = "dynamic"
    OPAQUE = "opaque"
    INFERRED = "inferred"


class ColumnTransformation(BaseModel):
    # "direct_map", "expression", "constant", "lookup", "dynamic" (S4 tokenizer
    # classification); "trunjob_context_param", "table_identity" (S5 cross-job
    # stitching); or the legacy LLM-pass value "aggregation".
    transformation_type: str = ""
    expression: str = ""
    human_explanation: str = ""


class LineageEntry(BaseModel):
    source_system: str = ""
    source_table: str = ""
    source_column: str = ""
    transformations: list[ColumnTransformation] = Field(default_factory=list)
    target_table: str = ""
    target_column: str = ""
    job_name: str = ""
    confidence: LineageConfidence = LineageConfidence.OPAQUE
    # -- S4 additions (deterministic scanner pass) --
    # Talend component unique_name upstream of source_table / downstream of
    # target_table, resolved via the job's `connections` (never the
    # unreliable per-component incoming/outgoing lists, see architecture
    # doc sec 1.2). Empty when the row name has no matching connection.
    source_component: str = ""
    target_component: str = ""
    # True only when source_table/source_column were resolved from a real
    # static reference (never true for constant/dynamic-only entries, which
    # still get emitted -- never silently dropped -- with empty source_*).
    resolved: bool = False
    # Unresolved identifier.field references found alongside this entry's
    # expression (globalMap.get, context.X, routine calls, ...), recorded
    # verbatim as "identifier.field" strings so nothing is silently dropped.
    dynamic_refs: list[str] = Field(default_factory=list)
    # -- S5 addition (cross-job stitching) --
    # Name of the job that owns source_table/source_column/source_component
    # when it differs from `job_name` (which always names the job that owns
    # target_table/target_column/target_component). Empty for every S4
    # intra-job entry, where source and target share the same job -- only
    # ever populated on `confidence: inferred` job-boundary edges, so its
    # presence (together with the confidence tier) is what distinguishes a
    # stitched cross-job edge from an intra-job one.
    source_job_name: str = ""


class LineageMatrix(BaseModel):
    """Column-level lineage tracing. Populated by `intodoc.lineage` through
    deterministic tMap, tXMLMap and TDM expression parsing rather than the
    abandoned LLM Pass 20 this schema originally shipped for."""
    entries: list[LineageEntry] = Field(default_factory=list)
    unmapped_columns: list[dict] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)


# ── Expression Catalog (Pass 21) ──────────────────────────────────


class ExpressionCatalogEntry(BaseModel):
    expression_id: str = ""
    raw_expression: str = ""
    human_explanation: str = ""
    complexity_score: int = 0  # 1-5
    expression_type: str = ""  # "field_map", "filter", "lookup", "ternary", "function_call", "sql_fragment", "java_code"
    location: str = ""  # "job_name / component_name"
    functions_used: list[str] = Field(default_factory=list)
    fields_referenced: list[str] = Field(default_factory=list)
    is_business_rule: bool = False


class ExpressionCatalog(BaseModel):
    """Pass 21 result: indexed expression catalog with complexity scores."""
    expressions: list[ExpressionCatalogEntry] = Field(default_factory=list)
    function_frequency: dict = Field(default_factory=dict)  # function_name -> count
    complexity_distribution: dict = Field(default_factory=dict)  # score -> count
    summary: dict = Field(default_factory=dict)


# ── Cost Tracking ───────────────────────────────────────────────────


class LLMCallRecord(BaseModel):
    pass_number: int
    chunk_id: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    timestamp: datetime = Field(default_factory=datetime.now)


class CostReport(BaseModel):
    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    budget_limit_usd: float = 5.0
    calls: list[LLMCallRecord] = Field(default_factory=list)


# ── Landscape Rollup (deterministic scanner pass, sibling of lineage.py) ──
#
# Rolls job/route-level scan facts (ProjectManifest + LineageMatrix) up into
# an L1/L2 systems-and-connections graph: which systems exist (databases,
# message brokers, SaaS APIs, ...), which applications (source_roots) the
# scan covers, and how they depend on each other -- both control flow
# ("what won't run if X is down") and data dependency ("if X writes bad
# data, who downstream consumes it"). See `intodoc.landscape` for the
# builder. Same philosophy as `LineageMatrix`: pure Python, no LLM, never
# fabricate an identity merge, never silently drop a fact that couldn't be
# rolled up (see `Landscape.unmapped`).


class LandscapeSystemEvidence(BaseModel):
    """One raw signal that contributed to a `LandscapeSystem` identity.

    `signal_type` is one of "context_group" | "metadata_connection" |
    "job_external_system" -- the three identity sources described in
    `intodoc.landscape`. `detail` carries only already-safe, non-secret
    facts (e.g. connection_type, source_root) -- never a raw host/URL.
    """
    signal_type: str
    label: str
    detail: dict = Field(default_factory=dict)


class LandscapeSystem(BaseModel):
    """A deduplicated system / external-node identity (database, message
    broker, SaaS API, file endpoint, ...)."""
    id: str
    name: str
    # database | messaging_broker | external_saas | file_endpoint |
    # rest_api | soap_api | internal | unknown
    kind: str = "unknown"
    evidence: list[LandscapeSystemEvidence] = Field(default_factory=list)
    source_roots: list[str] = Field(default_factory=list)


class LandscapeApplication(BaseModel):
    """One scanned Talend project identity represented at landscape level.

    ``source_root`` remains the canonical drill-down root for compatibility;
    ``source_roots`` records every physical copy when the same stable Talend
    project was bundled in more than one uploaded archive.
    """
    id: str
    source_root: str
    source_roots: list[str] = Field(default_factory=list)
    project_id: str = ""
    label: str = ""
    description: str = ""
    role: str = "execution"  # execution | support | shared_project
    artifact_count: int = 0
    kinds_breakdown: dict[str, int] = Field(default_factory=dict)


class LandscapeProvenance(BaseModel):
    """One drill-down-safe fact supporting a rolled-up landscape edge.

    The artifact is recorded both as its parser identity and as a qualified
    ``source_root::artifact_id`` identity so an L1/L2 answer can always be
    navigated back to the exact L3 artifact/component that supplied it.
    """
    artifact_id: str
    qualified_artifact_id: str
    source_root: str
    component_name: str = ""
    fact_type: str


class LandscapeEdge(BaseModel):
    """A rolled-up connection between two landscape nodes (application or
    system). Every edge MUST carry provenance so an L1 edge can be drilled
    down to the L3/L4 jobs/artifacts/lineage entries backing it -- an edge
    with empty `provenance` is a builder bug, never emitted intentionally."""
    source: str
    target: str
    source_kind: str  # application | system
    target_kind: str  # application | system
    dependency_type: str  # control_flow | data | integration | config
    mechanism: str = "unknown"  # jms|direct|direct-vm|rest|soap|file|db|unknown
    direction: str = "unknown"  # in|out|both|unknown
    reliability: str = "unknown"  # buffered|synchronous|unknown
    confidence: str = "unknown"  # certain|likely|inferred|unknown
    evidence_count: int = 0
    provenance: list[LandscapeProvenance] = Field(default_factory=list)


class LandscapeChannel(BaseModel):
    """An exact named channel available for L2 inspection.

    Placeholder/redacted channel values are intentionally excluded: they are
    insufficient to correlate a producer and consumer safely.
    """
    channel_type: str
    channel: str
    direction: str
    artifact_id: str
    qualified_artifact_id: str
    source_root: str
    component_name: str = ""
    fact_type: str = "artifact_channel"
    # Safe protocol/auth/TLS facts retained when a URI channel value itself
    # was redacted. Never contains a host, URI path, or credential.
    redaction_descriptor: RedactionDescriptor | None = None


class LandscapeInterface(BaseModel):
    """An exposed inbound/outbound interface surface for L2 inspection.

    Interface evidence intentionally does not create a peer relationship: an
    endpoint declaration alone cannot identify who calls it.
    """
    endpoint_type: str
    direction: str
    artifact_id: str
    qualified_artifact_id: str
    source_root: str
    component_name: str = ""
    fact_type: str = "artifact_endpoint"
    # Same safe descriptor contract as LandscapeChannel for URI-backed
    # REST/SOAP/file interfaces.
    redaction_descriptor: RedactionDescriptor | None = None


class LandscapeDiagnostic(BaseModel):
    """A computed finding surfaced alongside the graph (unread channels,
    unresolved cross-system refs, ...). `severity` is additive beyond the
    minimum {kind, description, evidence} shape -- "info" unless the
    builder can cheaply justify "warning" (e.g. a dead-letter-named
    write-only channel)."""
    kind: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    severity: str = "info"  # info | warning


class Landscape(BaseModel):
    """Output of `intodoc.landscape.build_landscape`, persisted as
    `scan/landscape.json` by `save_landscape` (mirrors
    `lineage.save_lineage_matrix`)."""
    systems: list[LandscapeSystem] = Field(default_factory=list)
    applications: list[LandscapeApplication] = Field(default_factory=list)
    edges: list[LandscapeEdge] = Field(default_factory=list)
    channels: list[LandscapeChannel] = Field(default_factory=list)
    interfaces: list[LandscapeInterface] = Field(default_factory=list)
    diagnostics: list[LandscapeDiagnostic] = Field(default_factory=list)
    # Anything that could not be rolled up cleanly -- never silently
    # dropped, matching `LineageMatrix.unmapped_columns`.
    unmapped: list[dict] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
