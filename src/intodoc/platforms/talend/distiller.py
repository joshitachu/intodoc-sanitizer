"""Talend distiller -- strip UI noise and prepare LLM-ready chunks."""

from __future__ import annotations

from intodoc.models import (
    AnalysisChunk,
    Component,
    ComponentParam,
    ParsedJob,
    ScanResult,
)
from intodoc.platforms.base_distiller import BaseDistiller

# ── Filter constants ────────────────────────────────────────────────

# Names to unconditionally strip
STRIP_PARAMS = frozenset({
    # UI / visual
    "HINT", "HELP", "COMMENT", "PREVIEW", "IMAGE",
    "COMP_DEFAULT_FILE_DIR", "CONNECTION_FORMAT",
    # Property / schema metadata
    "REPOSITORY_PROPERTY_TYPE", "REPOSITORY_SCHEMA_TYPE",
    "PROPERTY:REPOSITORY_PROPERTY_TYPE", "PROPERTY:REPOSITORY_SCHEMA_TYPE",
    "SCHEMA:SCHEMA_TYPE", "UNIQUE_NAME",
    "CHANGE_HASH_AND_EQUALS_FOR_BIGDECIMAL",
    # Stats / monitoring
    "TSTATCATCHER_STATS",
    # Boilerplate defaults (same on nearly every component)
    "MAPPING", "RESULT_SIZE", "TEMPORARY_DATASET_NAME",
    "BASE_FILE_PATH", "MEMORY_HEAP_MAX_SIZE",
    "FLUSHONROW_NUM",
    # Redacted placeholders (no information content)
    "[CREDENTIAL_PATH]", "AUTH_PASSWORD",
    # Formatting defaults (always the same across all jobs)
    "DECIMAL_SEPARATOR", "THOUSANDS_SEPARATOR", "ROWSEPARATOR", "CSVROWSEPARATOR",
    "FIELDSEPARATOR", "FIELD_DELIMITER", "ESCAPE_CHAR", "TEXT_ENCLOSURE",
    "ENCODING", "ENCODING:ENCODING_TYPE",
    # Internal Talend IDs / wiring
    "FAMILY", "SCHEMA_OPT_NUM",
    "SCHEMA_REJECT:SCHEMA_TYPE", "SCHEMA:REPOSITORY_SCHEMA_TYPE",
    "QUERYSTORE:QUERYSTORE_TYPE", "TRIGGER_INPUT_1:COMPONENT_LIST",
    "module.main.schema:SCHEMA_TYPE",
    # API endpoint defaults (always same URL)
    "REGION_ENDPOINT_BQ", "REGION_ENDPOINT_GS",
    # Boilerplate defaults always same value
    "NB_ROWS", "NB_RANDOM", "HEADER", "SPLIT_EVERY", "STREAMNAME",
    "FILENAMETEXT", "CONTEXT_NAME", "RECEIVE_TIMEOUT_DESC",
    # Dev-machine paths / internal settings
    "TEMP_DIR",
    # Loop defaults (always 1/true)
    "FROM", "STEP", "ITERATION", "WHILELOOP", "DECLARATION",
})

# Param name prefixes to strip
STRIP_PREFIXES = (
    "offsetLabel", "posX", "posY", "sizeX", "sizeY",
)

# Substrings in param name that indicate noise
STRIP_SUBSTRINGS = ("TOKEN", "SECRET", "WARNING")

# Default / boilerplate values to always strip
STRIP_VALUES = frozenset({
    "false", "0", "auto", "utf-8", "iso-8859-15", "2000000",
})

# CHECK (boolean) params to KEEP — all others stripped
KEEP_CHECK_PARAMS = frozenset({
    "DIE_ON_ERROR", "USE_BATCH_SIZE", "ENABLE_PARALLEL_EXECUTION",
    "USE_EXISTING_CONNECTION", "APPEND_MODE",
    "CREATE_TABLE_IF_NOT_EXISTS", "CREATE_TABLE_IF_NOT_EXIST",
    "USE_LEGACY_SQL",
})

# CLOSED_LIST params to KEEP — all others stripped
KEEP_CLOSED_LIST_PARAMS = frozenset({
    "TABLE_ACTION", "DATA_ACTION", "ACTION_ON_DATA", "ACTION_ON_TABLE",
    "WRITE_MODE", "DBTYPE", "TYPE", "DB_VERSION",
    "DATA_WRITE_MODEL", "KEYS_MANAGEMENT",
    "HTTP_METHOD", "VERB", "METHOD", "HTTP_VERB",
})

# Structural components kept even when all params are stripped
STRUCTURAL_COMPONENTS = frozenset({
    "tPrejob", "tPostjob", "tUnite", "tFlowToIterate",
})


class TalendDistiller(BaseDistiller):
    """Strip Talend-specific noise and group jobs into analysis chunks."""

    STRIP_PARAMS = STRIP_PARAMS
    STRIP_PREFIXES = STRIP_PREFIXES
    STRIP_SUBSTRINGS = STRIP_SUBSTRINGS
    STRIP_VALUES = STRIP_VALUES
    KEEP_CHECK_PARAMS = KEEP_CHECK_PARAMS
    KEEP_CLOSED_LIST_PARAMS = KEEP_CLOSED_LIST_PARAMS

    def __init__(self) -> None:
        super().__init__()
        # Populated during distill() — params constant across all jobs
        self._constant_params: set[str] = set()

    def distill(self, scan_result: ScanResult) -> list[AnalysisChunk]:
        """Group jobs into LLM-sized chunks by group, stripping noise."""
        # ── Phase 3.5: Compute project-wide constant params ──────────
        self._constant_params = self._find_constant_params(scan_result)

        # Delegate to base distill which calls self._distill_job() per job
        chunks = super().distill(scan_result)

        return chunks

    def _print_report(
        self,
        total_jobs: int,
        raw_tokens: int,
        distilled_tokens: int,
        chunk_count: int,
        **extra_stats: int,
    ) -> None:
        """Print report with Talend-specific constant_params_removed stat."""
        super()._print_report(
            total_jobs=total_jobs,
            raw_tokens=raw_tokens,
            distilled_tokens=distilled_tokens,
            chunk_count=chunk_count,
            constant_params_removed=len(self._constant_params),
            **extra_stats,
        )

    # ── Phase 3.5: Project-wide constant param detection ─────────────

    @staticmethod
    def _find_constant_params(scan_result: ScanResult) -> set[str]:
        """Find params that have only 1 unique value across ALL jobs.

        These carry zero information (the LLM can't distinguish jobs by them)
        and can be safely stripped from every component.

        Only triggers when the param appears on 3+ components (avoids
        false positives on small projects or single-job test cases).
        """
        param_value_sets: dict[str, set[str]] = {}
        param_occurrence_count: dict[str, int] = {}
        for job in scan_result.jobs:
            for comp in job.components:
                for p in comp.params:
                    val = str(p.value).strip().strip('"')
                    param_value_sets.setdefault(p.name, set()).add(val)
                    param_occurrence_count[p.name] = param_occurrence_count.get(p.name, 0) + 1

        return {
            name
            for name, vals in param_value_sets.items()
            if len(vals) <= 1 and param_occurrence_count.get(name, 0) >= 3
        }

    # ── Per-param filter ─────────────────────────────────────────────

    def _keep_param(self, p: ComponentParam) -> bool:
        """Decide whether a component parameter should be kept."""
        # 0. Strip project-wide constants (Phase 3.5)
        if p.name in self._constant_params:
            return False

        # 1. Strip None or empty
        if p.value is None or not str(p.value).strip().strip('"'):
            return False

        # 2. Strip by exact name
        if p.name in self.STRIP_PARAMS:
            return False

        # 3. Strip by prefix
        if any(p.name.startswith(pfx) for pfx in self.STRIP_PREFIXES):
            return False

        # 4. Strip by name substring
        name_upper = p.name.upper()
        if any(sub in name_upper for sub in self.STRIP_SUBSTRINGS):
            return False

        # 5. Strip default values
        val = str(p.value).strip().strip('"').lower()
        if val in self.STRIP_VALUES:
            return False

        # 6. Field-type filtering
        ft = (p.field_type or "").upper()
        if ft == "CHECK":
            return p.name in self.KEEP_CHECK_PARAMS
        if ft == "CLOSED_LIST":
            return p.name in self.KEEP_CLOSED_LIST_PARAMS

        # 7. Keep everything else (TEXT, MEMO, etc.)
        return True

    # ── Job distillation ──────────────────────────────────────────────

    def _distill_job(self, job: ParsedJob) -> ParsedJob:
        """Strip noise from a single job."""
        distilled_components: list[Component] = []
        for comp in job.components:
            clean = [p for p in comp.params if self._keep_param(p)]
            # Keep structural components even when empty
            if clean or comp.component_type in STRUCTURAL_COMPONENTS:
                distilled_components.append(
                    comp.model_copy(update={"params": clean})
                )

        return job.model_copy(update={"components": distilled_components})
