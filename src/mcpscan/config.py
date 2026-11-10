"""Project-level configuration loader for ``.mcpscan.yml`` / ``.mcpscan.yaml``.

Supports:
- ``fail_under``: minimum score threshold (overridden by CLI ``--fail-under``)
- ``select`` / ``ignore``: default rule filters
- ``suppress``: finding fingerprints to silence (with optional expiry date)
- ``output``: default export paths for each reporter format
- ``timeout``: default connection timeout

The CLI ``--config`` flag specifies an explicit path; without it the loader
auto-discovers ``.mcpscan.yml`` or ``.mcpscan.yaml`` in the working directory.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger(__name__)

# ---- YAML parser (graceful fallback) ----
_yaml_load: Any = None


def _get_yaml_loader():
    """Lazily import a YAML parser — prefer PyYAML, fall back to stdlib tomllib style."""
    global _yaml_load
    if _yaml_load is not None:
        return _yaml_load
    try:
        import yaml  # type: ignore[import-untyped]

        def _safe_load_yaml(data):
            return yaml.safe_load(data)

        _yaml_load = _safe_load_yaml
    except ImportError:
        # Minimal fallback: we don't ship PyYAML as a hard dep; if absent
        # and the user creates a config file we raise a clear error.
        _yaml_load = None
    return _yaml_load


# ---- Models ----


class SuppressionEntry(BaseModel):
    """A fingerprinted finding suppression with optional expiry."""

    fingerprint: str = Field(..., description="SHA-256 fingerprint of the finding to suppress")
    reason: str = Field("", description="Human-readable reason for suppression")
    expires: str | None = Field(
        None,
        description="ISO-8601 date (YYYY-MM-DD) after which the suppression expires",
    )

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        try:
            exp_date = date.fromisoformat(self.expires)
            return date.today() > exp_date
        except ValueError:
            logger.warning("Invalid expiry date '%s' in suppression for %s", self.expires, self.fingerprint)
            return False


class OutputDefaults(BaseModel):
    """Default export paths for reporter formats."""

    model_config = ConfigDict(populate_by_name=True)

    sarif: str | None = None
    json_path: str | None = Field(None, alias="json")
    html: str | None = None
    markdown: str | None = None

    @property
    def json(self) -> str | None:
        return self.json_path


class ScanConfig(BaseModel):
    """Root configuration model loaded from ``.mcpscan.yml``."""

    fail_under: int = Field(70, ge=0, le=100, description="Score threshold for CI/CD gates")
    timeout: int = Field(15, gt=0, description="Connection timeout in seconds")
    select: list[str] = Field(default_factory=list, description="Rule IDs to execute exclusively")
    ignore: list[str] = Field(default_factory=list, description="Rule IDs to skip")
    suppress: list[SuppressionEntry] = Field(default_factory=list, description="Finding suppressions")
    output: OutputDefaults = Field(default_factory=OutputDefaults, description="Default export paths")

    @field_validator("select", "ignore", mode="before")
    @classmethod
    def _coerce_rule_list(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [r.strip() for r in v.split(",") if r.strip()]
        if isinstance(v, list):
            return [str(r).strip() for r in v if str(r).strip()]
        return []


# ---- Fingerprinting ----


def compute_finding_fingerprint(
    rule_id: str,
    target_name: str,
    path: str | None = None,
) -> str:
    """Compute a stable SHA-256 fingerprint for a finding.

    The fingerprint is based on rule_id + target_name + path so that
    the same finding on the same component always produces the same hash,
    independent of description text changes across rule versions.
    """
    canonical = f"{rule_id}:{target_name}:{path or ''}"
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---- Loader ----


_CONFIG_FILENAMES = (".mcpscan.yml", ".mcpscan.yaml")


def load_config(
    explicit_path: str | None = None,
    search_dir: str | None = None,
) -> ScanConfig:
    """Load project configuration from a YAML file.

    Parameters
    ----------
    explicit_path:
        Explicit path from ``--config`` CLI flag. Raises ``FileNotFoundError``
        if specified but missing.
    search_dir:
        Directory to search for auto-discovery. Defaults to CWD.

    Returns
    -------
    ScanConfig:
        Parsed configuration, or defaults if no config file is found.
    """
    config_path: Path | None = None

    if explicit_path:
        config_path = Path(explicit_path)
        if not config_path.is_file():
            raise FileNotFoundError(f"Config file not found: {explicit_path}")
    else:
        base = Path(search_dir) if search_dir else Path.cwd()
        for name in _CONFIG_FILENAMES:
            candidate = base / name
            if candidate.is_file():
                config_path = candidate
                break

    if config_path is None:
        return ScanConfig()

    yaml_loader = _get_yaml_loader()
    if yaml_loader is None:
        raise ImportError(
            f"Found config file '{config_path}' but PyYAML is not installed. "
            "Install it with: pip install pyyaml"
        )

    raw_text = config_path.read_text(encoding="utf-8")
    data = yaml_loader(raw_text)

    if not isinstance(data, dict):
        logger.warning("Config file '%s' did not parse as a mapping; using defaults", config_path)
        return ScanConfig()

    return ScanConfig.model_validate(data)
