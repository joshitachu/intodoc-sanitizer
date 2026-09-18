"""Configuration via Pydantic Settings."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class RedactionLevel(str, Enum):
    """How aggressively to redact sensitive data before LLM exposure."""

    STANDARD = "standard"  # Passwords + IPs + FQDNs + URLs + emails + usernames
    STRICT = "strict"      # Standard + file paths + database/schema names + cloud IDs
    PARANOID = "paranoid"  # Redact ALL context variable values


class IntodocConfig(BaseSettings):
    """All configurable options for intodoc."""

    model_config = {"env_prefix": "INTODOC_"}

    # Paths
    repo_path: Path = Field(default=Path("."), description="Root of the integration codebase to scan")
    output_dir: Path = Field(default=Path("./intodoc-output"), description="Where generated docs are written")
    cache_dir: Path = Field(default=Path("./.intodoc_cache"), description="Cache directory for LLM responses")
    state_file: Path = Field(default=Path("./.intodoc_state.json"), description="Incremental state tracking")

    # Platform
    platform: str = Field(default="talend", description="Integration platform: talend, mulesoft, dbt, etc.")

    # LLM — provider-agnostic via LiteLLM
    llm_provider: str = Field(default="anthropic", description="LLM provider: anthropic, openai, groq, kimi, ollama, etc.")
    llm_api_key: str = Field(default="", description="API key for the LLM provider")
    llm_base_url: str = Field(default="", description="Custom base URL (for Ollama, self-hosted, etc.)")
    model_default: str = Field(default="claude-sonnet-4-5-20250929", description="Model for passes 1-9 (any litellm model string)")
    model_synthesis: str = Field(default="claude-opus-4-6", description="Model for pass 10 (synthesis)")
    max_tokens: int = Field(default=8192, description="Max output tokens per LLM call")
    cost_limit: float = Field(default=5.0, description="Hard budget limit in USD")
    max_concurrent: int = Field(default=5, description="Max concurrent LLM calls")

    # Chunker
    target_chunk_tokens: int = Field(default=30_000, description="Target tokens per analysis chunk")

    # Qdrant
    qdrant_url: str = Field(default="", description="Qdrant endpoint URL for RAG export")
    qdrant_collection: str = Field(default="intodoc", description="Qdrant collection name")

    # Behavior
    verbose: bool = Field(default=False, description="Enable verbose logging")
    skip_git: bool = Field(default=False, description="Skip git history analysis")
    passes: list[int] = Field(default_factory=lambda: list(range(1, 22)), description="Which passes to run (1-21)")

    # Redaction
    redaction_level: RedactionLevel = Field(default=RedactionLevel.STANDARD, description="Redaction aggressiveness: standard, strict, paranoid")
    redaction_config: Path | None = Field(default=None, description="Path to .intodoc-redact.yaml with custom redaction rules")
    redaction_audit: bool = Field(default=True, description="Write redaction_report.json to output dir")
    allow_redaction_failures: bool = Field(
        default=False,
        description="If True, a failed post-scan redaction verification only warns instead of aborting the scan",
    )
