"""Base distiller -- generic chunking, context compaction, and defaults extraction.

Platform-specific distillers extend this class and override ``_distill_job``
to apply their own noise-filtering rules (e.g. stripping Talend UI params).
"""

from __future__ import annotations

import hashlib

from rich.console import Console

from intodoc.models import (
    AnalysisChunk,
    MetadataConnection,
    ParsedJob,
    ProjectManifest,
    Routine,
    ScanResult,
)

console = Console()


class BaseDistiller:
    """Group jobs into LLM-sized analysis chunks with generic optimisations.

    Subclasses override ``_distill_job`` for platform-specific filtering.
    """

    def __init__(self) -> None:
        pass

    # ── Abstract hook ────────────────────────────────────────────────

    def _distill_job(self, job: ParsedJob) -> ParsedJob:
        """Override in subclasses for platform-specific filtering."""
        return job  # Base: no filtering

    # ── Main entry ───────────────────────────────────────────────────

    def distill(self, scan_result: ScanResult) -> list[AnalysisChunk]:
        """Group jobs into LLM-sized chunks by group, stripping noise."""
        # Track raw token estimate using fast Pydantic serializer (3.1/3.2)
        raw_tokens = sum(len(j.model_dump_json()) for j in scan_result.jobs) // 4

        # Group jobs by group
        group_jobs: dict[str, list[ParsedJob]] = {}
        for job in scan_result.jobs:
            group = job.group or "Global"
            group_jobs.setdefault(group, []).append(job)

        chunks: list[AnalysisChunk] = []
        # Cache per-job token estimates to avoid re-serialization (3.1)
        job_token_cache: dict[int, int] = {}

        for group, jobs in sorted(group_jobs.items()):
            # Distill each job
            distilled_jobs = [self._distill_job(j) for j in jobs]

            # Compute per-job token estimates once (3.2)
            group_tokens = 0
            for dj in distilled_jobs:
                jid = id(dj)
                if jid not in job_token_cache:
                    job_token_cache[jid] = len(dj.model_dump_json()) // 4
                group_tokens += job_token_cache[jid]

            # If chunk is too large, split into sub-chunks
            if group_tokens > 40_000:
                sub_chunks = self._split_chunk(
                    group, distilled_jobs, scan_result, job_token_cache
                )
                chunks.extend(sub_chunks)
            else:
                chunk_id = f"{group}_all"
                content_bytes = b"".join(
                    dj.model_dump_json().encode() for dj in distilled_jobs
                )
                sha = hashlib.sha256(content_bytes).hexdigest()

                # Find related connections and contexts
                related_conns = self._match_connections_for_jobs(distilled_jobs, scan_result)
                related_ctxs = [
                    c for c in scan_result.context_groups
                    if group.lower() in c.name.lower()
                ]
                related_routines = self._match_routines_for_jobs(distilled_jobs, scan_result)

                chunks.append(AnalysisChunk(
                    chunk_id=chunk_id,
                    group=group,
                    jobs=distilled_jobs,
                    related_connections=related_conns,
                    related_contexts=related_ctxs,
                    related_routines=related_routines,
                    token_estimate=group_tokens,
                    sha256=sha,
                ))

        # ── Phase 3.3: Filter manifest per-chunk ─────────────────────
        for chunk in chunks:
            job_ids = {j.job_id or j.name for j in chunk.jobs}
            chunk.manifest = self._filter_manifest(scan_result.manifest, job_ids)

        # Deduplicate inline contexts that duplicate chunk-level contexts
        for chunk in chunks:
            self._dedup_contexts(chunk)

        # ── Phase 3.7: Compact context variable environments ─────────
        for chunk in chunks:
            self._compact_contexts(chunk)

        # ── Phase 3.6: Extract chunk-level defaults ──────────────────
        for chunk in chunks:
            self._extract_defaults(chunk)

        # Recompute token estimates after all compression passes
        for chunk in chunks:
            chunk.token_estimate = sum(
                len(j.model_dump_json()) // 4 for j in chunk.jobs
            )

        # Print reduction report
        distilled_tokens = sum(c.token_estimate for c in chunks)
        self._print_report(
            total_jobs=len(scan_result.jobs),
            raw_tokens=raw_tokens,
            distilled_tokens=distilled_tokens,
            chunk_count=len(chunks),
        )

        return chunks

    # ── Chunking helpers ─────────────────────────────────────────────

    def _split_chunk(
        self,
        group: str,
        jobs: list[ParsedJob],
        scan_result: ScanResult,
        job_token_cache: dict[int, int],
    ) -> list[AnalysisChunk]:
        """Split a large group into smaller chunks (~30K tokens each)."""
        chunks: list[AnalysisChunk] = []
        current_jobs: list[ParsedJob] = []
        current_tokens = 0
        chunk_idx = 0

        for job in jobs:
            jid = id(job)
            if jid not in job_token_cache:
                job_token_cache[jid] = len(job.model_dump_json()) // 4
            job_tokens = job_token_cache[jid]

            if current_tokens + job_tokens > 30_000 and current_jobs:
                chunks.append(
                    self._make_chunk(group, chunk_idx, current_jobs, scan_result)
                )
                chunk_idx += 1
                current_jobs = []
                current_tokens = 0

            current_jobs.append(job)
            current_tokens += job_tokens

        if current_jobs:
            chunks.append(
                self._make_chunk(group, chunk_idx, current_jobs, scan_result)
            )

        return chunks

    def _make_chunk(
        self, group: str, idx: int, jobs: list[ParsedJob],
        scan_result: ScanResult,
    ) -> AnalysisChunk:
        """Create an AnalysisChunk from a list of jobs."""
        content_bytes = b"".join(j.model_dump_json().encode() for j in jobs)
        token_est = len(content_bytes) // 4
        return AnalysisChunk(
            chunk_id=f"{group}_{idx}",
            group=group,
            jobs=jobs,
            related_connections=self._match_connections_for_jobs(jobs, scan_result),
            related_contexts=[
                c for c in scan_result.context_groups
                if group.lower() in c.name.lower()
            ],
            related_routines=self._match_routines_for_jobs(jobs, scan_result),
            token_estimate=token_est,
            sha256=hashlib.sha256(content_bytes).hexdigest(),
        )

    # ── Phase 3.3: Manifest filtering per-chunk ──────────────────────

    @staticmethod
    def _filter_manifest(
        manifest: ProjectManifest, job_names: set[str]
    ) -> ProjectManifest:
        """Return a manifest containing only edges involving the chunk's jobs."""
        return ProjectManifest(
            job_calls={k: v for k, v in manifest.job_calls.items() if k in job_names},
            job_called_by={k: v for k, v in manifest.job_called_by.items() if k in job_names},
            job_connections_used={k: v for k, v in manifest.job_connections_used.items() if k in job_names},
            connection_used_by={k: v for k, v in manifest.connection_used_by.items()
                                if any(j in job_names for j in v)},
            job_contexts_used={k: v for k, v in manifest.job_contexts_used.items() if k in job_names},
            routines_used_by={k: v for k, v in manifest.routines_used_by.items()
                              if any(j in job_names for j in v)},
            job_groups={k: v for k, v in manifest.job_groups.items() if k in job_names},
            job_external_systems={k: v for k, v in manifest.job_external_systems.items() if k in job_names},
            source_roots=manifest.source_roots,
            job_source_roots={k: v for k, v in manifest.job_source_roots.items() if k in job_names},
            job_files={k: v for k, v in manifest.job_files.items() if k in job_names},
            unresolved_job_calls={k: v for k, v in manifest.unresolved_job_calls.items() if k in job_names},
            context_used_by={k: [j for j in v if j in job_names] for k, v in manifest.context_used_by.items()
                             if any(j in job_names for j in v)},
            context_metadata=manifest.context_metadata,
            job_context_links={k: v for k, v in manifest.job_context_links.items() if k in job_names},
            unresolved_context_refs={k: v for k, v in manifest.unresolved_context_refs.items() if k in job_names},
            job_support_roots={k: v for k, v in manifest.job_support_roots.items() if k in job_names},
            artifact_kinds={k: v for k, v in manifest.artifact_kinds.items() if k in job_names},
            artifact_relations=[
                relation for relation in manifest.artifact_relations
                if relation.get("source") in job_names or relation.get("target") in job_names
            ],
            artifact_channels=[
                channel for channel in manifest.artifact_channels
                if channel.get("artifact") in job_names
            ],
            artifact_endpoints=[
                endpoint for endpoint in manifest.artifact_endpoints
                if endpoint.get("artifact") in job_names
            ],
            artifact_resources=[
                resource for resource in manifest.artifact_resources
                if resource.get("artifact") in job_names
            ],
        )

    # ── Connection matching ──────────────────────────────────────────

    @staticmethod
    def _match_connections_for_jobs(
        jobs: list[ParsedJob], scan_result: ScanResult,
    ) -> list[MetadataConnection]:
        """Match metadata connections to jobs via component REPOSITORY refs."""
        ref_names: set[str] = set()
        for job in jobs:
            for comp in job.components:
                if comp.metadata_connection_ref:
                    ref_names.update(
                        ref.strip()
                        for ref in comp.metadata_connection_ref.split(",")
                        if ref.strip()
                    )

        matched: dict[str, MetadataConnection] = {}
        for conn in scan_result.metadata_connections:
            if conn.name in ref_names:
                matched[conn.name] = conn

        return list(matched.values())

    @staticmethod
    def _match_routines_for_jobs(
        jobs: list[ParsedJob], scan_result: ScanResult,
    ) -> list[Routine]:
        """Match routines to jobs via job.raw_routines references."""
        ref_names: set[str] = set()
        for job in jobs:
            ref_names.update(job.raw_routines)

        if not ref_names:
            return []

        return [r for r in scan_result.routines if r.name in ref_names and not r.is_system]

    # ── Context deduplication ────────────────────────────────────────

    def _dedup_contexts(self, chunk: AnalysisChunk) -> None:
        """Remove inline job context_groups whose variables are already in chunk.related_contexts."""
        if not chunk.related_contexts:
            return

        # Build set of variable names already present at chunk level
        chunk_var_names: set[str] = set()
        for cg in chunk.related_contexts:
            for var in cg.variables:
                chunk_var_names.add(var.name)

        if not chunk_var_names:
            return

        for job in chunk.jobs:
            deduped: list = []
            for cg in job.context_groups:
                # Keep the group if it has any variable NOT already in chunk contexts
                remaining_vars = [
                    v for v in cg.variables if v.name not in chunk_var_names
                ]
                if remaining_vars:
                    deduped.append(cg.model_copy(update={"variables": remaining_vars}))
            job.context_groups = deduped

    # ── Phase 3.7: Compact context variable environments ─────────────

    @staticmethod
    def _compact_contexts(chunk: AnalysisChunk) -> None:
        """Compact context variable environments.

        - If all environment values are identical -> keep only one representative.
        - If the value is a context reference -> keep only the reference.
        """
        all_ctx_groups = list(chunk.related_contexts)
        for job in chunk.jobs:
            all_ctx_groups.extend(job.context_groups)

        for cg in all_ctx_groups:
            for var in cg.variables:
                if not var.values:
                    continue
                unique_vals = set(var.values.values())
                if len(unique_vals) == 1:
                    # All envs have the same value -- keep only one
                    representative_val = next(iter(unique_vals))
                    var.values = {"_default": representative_val}

    # ── Phase 3.6: Chunk-level param defaults ────────────────────────

    @staticmethod
    def _extract_defaults(chunk: AnalysisChunk) -> None:
        """Extract params where >90% of components share the same value.

        These become chunk-level defaults; only exceptions are kept on components.
        The defaults are stored in chunk stats for prompt builders to reference.
        """
        # Count value frequencies per param name across all components in the chunk
        param_counts: dict[str, dict[str, int]] = {}  # param_name -> {value -> count}
        total_components = 0

        for job in chunk.jobs:
            for comp in job.components:
                total_components += 1
                for p in comp.params:
                    param_counts.setdefault(p.name, {})
                    val = str(p.value).strip()
                    param_counts[p.name][val] = param_counts[p.name].get(val, 0) + 1

        if total_components < 5:
            return  # Too few components for meaningful defaults

        # Find params where >90% share the same value
        defaults: dict[str, str] = {}
        for name, value_counts in param_counts.items():
            total_occurrences = sum(value_counts.values())
            if total_occurrences < 5:
                continue
            top_value, top_count = max(value_counts.items(), key=lambda x: x[1])
            if top_count / total_occurrences >= 0.9:
                defaults[name] = top_value

        if not defaults:
            return

        # Strip default-value params from individual components; keep exceptions
        for job in chunk.jobs:
            for comp in job.components:
                comp.params = [
                    p for p in comp.params
                    if p.name not in defaults
                    or str(p.value).strip() != defaults[p.name]
                ]

    # ── Reporting ────────────────────────────────────────────────────

    def _print_report(
        self,
        total_jobs: int,
        raw_tokens: int,
        distilled_tokens: int,
        chunk_count: int,
        **extra_stats: int,
    ) -> None:
        """Print before/after token reduction stats."""
        if raw_tokens == 0:
            return
        reduction_pct = (1 - distilled_tokens / raw_tokens) * 100
        avg_per_chunk = distilled_tokens // chunk_count if chunk_count else 0

        console.print()
        console.print("[bold cyan]--- Distiller Token Reduction Report ---[/bold cyan]")
        console.print(f"  Total jobs:              {total_jobs:,}")
        console.print(f"  Raw tokens:              {raw_tokens:,}")
        console.print(f"  Distilled tokens:        {distilled_tokens:,}")
        console.print(f"  Reduction:               {reduction_pct:.1f}%")
        console.print(f"  Chunks:                  {chunk_count}")
        console.print(f"  Avg tokens/chunk:        {avg_per_chunk:,}")
        for label, value in extra_stats.items():
            if value:
                # Convert snake_case to display label
                display = label.replace("_", " ").capitalize()
                console.print(f"  {display + ':':25s}{value}")
        console.print("[bold cyan]----------------------------------------[/bold cyan]")
        console.print()
