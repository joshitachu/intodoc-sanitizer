"""Tests for TalendDistiller filtering logic."""

from __future__ import annotations

import pytest

from intodoc.models import (
    AnalysisChunk,
    Component,
    ComponentParam,
    ContextGroup,
    ContextVariable,
    ParsedJob,
    ScanResult,
)
from intodoc.platforms.talend.distiller import TalendDistiller


@pytest.fixture
def distiller():
    return TalendDistiller()


def _param(name: str, value: str, field_type: str = "TEXT") -> ComponentParam:
    return ComponentParam(name=name, value=value, field_type=field_type)


def _component(
    name: str = "tMSSqlInput_1",
    comp_type: str = "tMSSqlInput",
    params: list[ComponentParam] | None = None,
) -> Component:
    return Component(
        unique_name=name,
        component_type=comp_type,
        params=params or [],
    )


def _job(
    name: str = "TestJob",
    components: list[Component] | None = None,
    context_groups: list[ContextGroup] | None = None,
) -> ParsedJob:
    return ParsedJob(
        name=name,
        path=f"BRA/{name}_0.1.item",
        group="BRA",
        components=components or [],
        context_groups=context_groups or [],
    )


def _scan_result(jobs: list[ParsedJob] | None = None) -> ScanResult:
    return ScanResult(
        platform="talend",
        repo_root="/fake",
        jobs=jobs or [],
    )


# ── Name-based stripping ─────────────────────────────────────────


class TestNameStripping:
    def test_strips_hint(self, distiller):
        p = _param("HINT", "some hint text")
        assert distiller._keep_param(p) is False

    def test_strips_help(self, distiller):
        p = _param("HELP", "help text")
        assert distiller._keep_param(p) is False

    def test_strips_comment(self, distiller):
        p = _param("COMMENT", "a comment")
        assert distiller._keep_param(p) is False

    def test_strips_preview(self, distiller):
        p = _param("PREVIEW", "preview data")
        assert distiller._keep_param(p) is False

    def test_strips_image(self, distiller):
        p = _param("IMAGE", "/path/to/image.png")
        assert distiller._keep_param(p) is False

    def test_strips_tstatcatcher(self, distiller):
        p = _param("TSTATCATCHER_STATS", "true", "CHECK")
        assert distiller._keep_param(p) is False

    def test_strips_mapping(self, distiller):
        p = _param("MAPPING", "some_mapping")
        assert distiller._keep_param(p) is False

    def test_strips_unique_name(self, distiller):
        p = _param("UNIQUE_NAME", "tMSSqlInput_1")
        assert distiller._keep_param(p) is False

    def test_strips_repository_property_type(self, distiller):
        p = _param("REPOSITORY_PROPERTY_TYPE", "some_id")
        assert distiller._keep_param(p) is False

    def test_keeps_query(self, distiller):
        p = _param("QUERY", "SELECT * FROM table")
        assert distiller._keep_param(p) is True

    def test_keeps_dbname(self, distiller):
        p = _param("DBNAME", "mydb")
        assert distiller._keep_param(p) is True


# ── Prefix-based stripping ────────────────────────────────────────


class TestPrefixStripping:
    def test_strips_posx(self, distiller):
        p = _param("posX", "123")
        assert distiller._keep_param(p) is False

    def test_strips_posy(self, distiller):
        p = _param("posY", "456")
        assert distiller._keep_param(p) is False

    def test_strips_sizex(self, distiller):
        p = _param("sizeX", "100")
        assert distiller._keep_param(p) is False

    def test_strips_offsetlabel(self, distiller):
        p = _param("offsetLabelX", "0")
        assert distiller._keep_param(p) is False

    def test_strips_property_repository_refs(self, distiller):
        p = _param("PROPERTY:REPOSITORY_PROPERTY_TYPE", "some_id")
        assert distiller._keep_param(p) is False

    def test_keeps_property_type(self, distiller):
        p = _param("PROPERTY:PROPERTY_TYPE", "REPOSITORY")
        assert distiller._keep_param(p) is True


# ── Substring-based stripping ─────────────────────────────────────


class TestSubstringStripping:
    def test_strips_token_param(self, distiller):
        p = _param("ACCESS_TOKEN", "abc123")
        assert distiller._keep_param(p) is False

    def test_strips_secret_param(self, distiller):
        p = _param("CLIENT_SECRET", "xyz789")
        assert distiller._keep_param(p) is False

    def test_strips_warning_param(self, distiller):
        p = _param("DEPRECATION_WARNING", "old API")
        assert distiller._keep_param(p) is False

    def test_keeps_endpoint_param(self, distiller):
        p = _param("REST_ENDPOINT", "https://api.example.com")
        assert distiller._keep_param(p) is True


# ── Value-based stripping ─────────────────────────────────────────


class TestValueStripping:
    def test_strips_false(self, distiller):
        p = _param("SOME_FLAG", "false")
        assert distiller._keep_param(p) is False

    def test_strips_zero(self, distiller):
        p = _param("SOME_COUNT", "0")
        assert distiller._keep_param(p) is False

    def test_strips_auto(self, distiller):
        p = _param("ENCODING", "auto")
        assert distiller._keep_param(p) is False

    def test_strips_utf8(self, distiller):
        p = _param("ENCODING", "utf-8")
        assert distiller._keep_param(p) is False

    def test_strips_iso_encoding(self, distiller):
        p = _param("ENCODING", "iso-8859-15")
        assert distiller._keep_param(p) is False

    def test_strips_default_buffer(self, distiller):
        p = _param("BUFFER_SIZE", "2000000")
        assert distiller._keep_param(p) is False

    def test_strips_quoted_false(self, distiller):
        p = _param("SOME_FLAG", '"false"')
        assert distiller._keep_param(p) is False

    def test_strips_empty_value(self, distiller):
        p = _param("FIELD", "")
        assert distiller._keep_param(p) is False

    def test_strips_whitespace_only(self, distiller):
        p = _param("FIELD", "   ")
        assert distiller._keep_param(p) is False

    def test_strips_quoted_empty(self, distiller):
        p = _param("FIELD", '""')
        assert distiller._keep_param(p) is False

    def test_keeps_true(self, distiller):
        """'true' is NOT in STRIP_VALUES — only CHECK field_type filtering applies."""
        p = _param("SOME_PARAM", "true")
        assert distiller._keep_param(p) is True

    def test_keeps_nonzero(self, distiller):
        p = _param("BATCH_SIZE", "1000")
        assert distiller._keep_param(p) is True


# ── CHECK field_type filtering ────────────────────────────────────


class TestCheckFiltering:
    def test_keeps_die_on_error(self, distiller):
        p = _param("DIE_ON_ERROR", "true", "CHECK")
        assert distiller._keep_param(p) is True

    def test_keeps_use_batch_size(self, distiller):
        p = _param("USE_BATCH_SIZE", "true", "CHECK")
        assert distiller._keep_param(p) is True

    def test_keeps_enable_parallel(self, distiller):
        p = _param("ENABLE_PARALLEL_EXECUTION", "true", "CHECK")
        assert distiller._keep_param(p) is True

    def test_strips_unknown_check(self, distiller):
        p = _param("ACTIVATE", "true", "CHECK")
        assert distiller._keep_param(p) is False

    def test_strips_label_check(self, distiller):
        p = _param("LABEL", "some_label", "CHECK")
        assert distiller._keep_param(p) is False

    def test_strips_random_check(self, distiller):
        p = _param("SOME_RANDOM_BOOLEAN", "true", "CHECK")
        assert distiller._keep_param(p) is False


# ── CLOSED_LIST field_type filtering ──────────────────────────────


class TestClosedListFiltering:
    def test_keeps_table_action(self, distiller):
        p = _param("TABLE_ACTION", "CREATE_IF_NOT_EXISTS", "CLOSED_LIST")
        assert distiller._keep_param(p) is True

    def test_keeps_write_mode(self, distiller):
        p = _param("WRITE_MODE", "INSERT", "CLOSED_LIST")
        assert distiller._keep_param(p) is True

    def test_keeps_dbtype(self, distiller):
        p = _param("DBTYPE", "MSSQL", "CLOSED_LIST")
        assert distiller._keep_param(p) is True

    def test_strips_auth_mode_closed(self, distiller):
        p = _param("AUTH_MODE", "BASIC", "CLOSED_LIST")
        assert distiller._keep_param(p) is False

    def test_strips_text_enclosure_closed(self, distiller):
        p = _param("TEXT_ENCLOSURE", '"', "CLOSED_LIST")
        assert distiller._keep_param(p) is False

    def test_strips_escape_char_closed(self, distiller):
        p = _param("ESCAPE_CHAR", "\\", "CLOSED_LIST")
        assert distiller._keep_param(p) is False


# ── Empty component dropping ──────────────────────────────────────


class TestEmptyComponentDropping:
    def test_drops_component_with_no_surviving_params(self, distiller):
        comp = _component(params=[_param("HINT", "noise"), _param("PREVIEW", "more noise")])
        job = _job(components=[comp])
        result = distiller._distill_job(job)
        assert len(result.components) == 0

    def test_keeps_component_with_surviving_params(self, distiller):
        comp = _component(params=[
            _param("HINT", "noise"),
            _param("QUERY", "SELECT 1"),
        ])
        job = _job(components=[comp])
        result = distiller._distill_job(job)
        assert len(result.components) == 1
        assert result.components[0].params[0].name == "QUERY"

    def test_keeps_structural_component_even_if_empty(self, distiller):
        comp = _component(
            name="tPrejob_1",
            comp_type="tPrejob",
            params=[_param("HINT", "noise")],
        )
        job = _job(components=[comp])
        result = distiller._distill_job(job)
        assert len(result.components) == 1
        assert result.components[0].component_type == "tPrejob"
        assert len(result.components[0].params) == 0

    def test_keeps_tpostjob_structural(self, distiller):
        comp = _component(
            name="tPostjob_1",
            comp_type="tPostjob",
            params=[],
        )
        job = _job(components=[comp])
        result = distiller._distill_job(job)
        assert len(result.components) == 1


# ── Context deduplication ─────────────────────────────────────────


class TestContextDedup:
    def test_removes_fully_duplicated_inline_contexts(self, distiller):
        chunk_ctx = ContextGroup(
            name="BRA_env",
            variables=[
                ContextVariable(name="HOST", values={"Default": "localhost"}),
                ContextVariable(name="PORT", values={"Default": "1433"}),
            ],
        )
        inline_ctx = ContextGroup(
            name="inline",
            variables=[
                ContextVariable(name="HOST", values={"Default": "localhost"}),
                ContextVariable(name="PORT", values={"Default": "1433"}),
            ],
        )
        job = _job(context_groups=[inline_ctx])
        chunk = AnalysisChunk(
            chunk_id="BRA_all",
            group="BRA",
            jobs=[job],
            related_contexts=[chunk_ctx],
        )

        distiller._dedup_contexts(chunk)
        assert len(chunk.jobs[0].context_groups) == 0

    def test_keeps_unique_inline_vars(self, distiller):
        chunk_ctx = ContextGroup(
            name="BRA_env",
            variables=[
                ContextVariable(name="HOST", values={"Default": "localhost"}),
            ],
        )
        inline_ctx = ContextGroup(
            name="inline",
            variables=[
                ContextVariable(name="HOST", values={"Default": "localhost"}),
                ContextVariable(name="CUSTOM_VAR", values={"Default": "special"}),
            ],
        )
        job = _job(context_groups=[inline_ctx])
        chunk = AnalysisChunk(
            chunk_id="BRA_all",
            group="BRA",
            jobs=[job],
            related_contexts=[chunk_ctx],
        )

        distiller._dedup_contexts(chunk)
        assert len(chunk.jobs[0].context_groups) == 1
        assert chunk.jobs[0].context_groups[0].variables[0].name == "CUSTOM_VAR"

    def test_no_dedup_without_chunk_contexts(self, distiller):
        inline_ctx = ContextGroup(
            name="inline",
            variables=[
                ContextVariable(name="HOST", values={"Default": "localhost"}),
            ],
        )
        job = _job(context_groups=[inline_ctx])
        chunk = AnalysisChunk(
            chunk_id="BRA_all",
            group="BRA",
            jobs=[job],
            related_contexts=[],
        )

        distiller._dedup_contexts(chunk)
        assert len(chunk.jobs[0].context_groups) == 1


# ── End-to-end token reduction ────────────────────────────────────


class TestEndToEndReduction:
    def test_distill_reduces_tokens(self, distiller):
        """A job with lots of noise should produce fewer tokens after distillation."""
        noisy_params = [
            _param("HINT", "hint text"),
            _param("HELP", "help text"),
            _param("COMMENT", "comment text"),
            _param("PREVIEW", "preview"),
            _param("IMAGE", "/img.png"),
            _param("TSTATCATCHER_STATS", "false", "CHECK"),
            _param("ACTIVATE", "true", "CHECK"),
            _param("LABEL", "some_label", "CHECK"),
            _param("AUTH_MODE", "BASIC", "CLOSED_LIST"),
            _param("ENCODING", "utf-8"),
            _param("SOME_FLAG", "false"),
            _param("posX", "123"),
            _param("posY", "456"),
            _param("MAPPING", "default"),
            _param("RESULT_SIZE", "100"),
            # Only these should survive
            _param("QUERY", "SELECT * FROM orders"),
            _param("DBNAME", "production_db"),
            _param("TABLE_ACTION", "CREATE_IF_NOT_EXISTS", "CLOSED_LIST"),
            _param("DIE_ON_ERROR", "true", "CHECK"),
        ]
        comp = _component(params=noisy_params)
        job = _job(components=[comp])
        scan = _scan_result([job])

        chunks = distiller.distill(scan)
        assert len(chunks) == 1

        result_job = chunks[0].jobs[0]
        assert len(result_job.components) == 1
        surviving_names = {p.name for p in result_job.components[0].params}
        assert surviving_names == {"QUERY", "DBNAME", "TABLE_ACTION", "DIE_ON_ERROR"}

    def test_distill_drops_empty_components(self, distiller):
        """Components with only noise params should be dropped entirely."""
        noise_comp = _component(
            name="tLogRow_1",
            comp_type="tLogRow",
            params=[
                _param("HINT", "hint"),
                _param("ACTIVATE", "true", "CHECK"),
            ],
        )
        good_comp = _component(
            name="tMSSqlInput_1",
            comp_type="tMSSqlInput",
            params=[_param("QUERY", "SELECT 1")],
        )
        job = _job(components=[noise_comp, good_comp])
        scan = _scan_result([job])

        chunks = distiller.distill(scan)
        result_job = chunks[0].jobs[0]
        assert len(result_job.components) == 1
        assert result_job.components[0].component_type == "tMSSqlInput"

    def test_distill_produces_chunks(self, distiller):
        """Multiple jobs in same group go into one chunk."""
        jobs = [
            _job(name="Job1", components=[_component(params=[_param("QUERY", "SELECT 1")])]),
            _job(name="Job2", components=[_component(params=[_param("QUERY", "SELECT 2")])]),
        ]
        scan = _scan_result(jobs)
        chunks = distiller.distill(scan)
        assert len(chunks) == 1
        assert len(chunks[0].jobs) == 2

    def test_distill_multiple_groups(self, distiller):
        """Jobs in different groups produce separate chunks."""
        job1 = ParsedJob(name="Job1", path="BRA/Job1_0.1.item", group="BRA",
                         components=[_component(params=[_param("QUERY", "SELECT 1")])])
        job2 = ParsedJob(name="Job2", path="NLD/Job2_0.1.item", group="NLD",
                         components=[_component(params=[_param("QUERY", "SELECT 2")])])
        scan = _scan_result([job1, job2])
        chunks = distiller.distill(scan)
        assert len(chunks) == 2
        groups = {c.group for c in chunks}
        assert groups == {"BRA", "NLD"}
