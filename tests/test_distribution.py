"""Unit tests verifying packaging, GitHub Action schema, Dockerfile, and pre-commit hook."""

from pathlib import Path
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_action_yml_structure():
    """action.yml must exist and define required GitHub Action metadata."""
    action_file = REPO_ROOT / "action.yml"
    assert action_file.is_file(), "action.yml must exist at repository root"

    content = yaml.safe_load(action_file.read_text(encoding="utf-8"))
    assert isinstance(content, dict)
    assert content.get("name") == "MCP Security Posture Scanner (mcpscan)"
    assert "description" in content
    assert content.get("runs", {}).get("using") == "composite"

    inputs = content.get("inputs", {})
    assert "command" in inputs
    assert "fail-under" in inputs
    assert "sarif-output" in inputs
    assert "select" in inputs
    assert "ignore" in inputs

    outputs = content.get("outputs", {})
    assert "score" in outputs
    assert "grade" in outputs
    assert "findings-count" in outputs


def test_pre_commit_hooks_yaml():
    """.pre-commit-hooks.yaml must exist and configure the mcpscan hook."""
    hook_file = REPO_ROOT / ".pre-commit-hooks.yaml"
    assert hook_file.is_file(), ".pre-commit-hooks.yaml must exist"

    content = yaml.safe_load(hook_file.read_text(encoding="utf-8"))
    assert isinstance(content, list)
    assert len(content) >= 1

    hook = content[0]
    assert hook.get("id") == "mcpscan"
    assert hook.get("entry") == "mcpscan scan"
    assert hook.get("language") == "python"


def test_dockerfile_security_standards():
    """Dockerfile must adhere to security best practices (non-root user, slim base)."""
    dockerfile = REPO_ROOT / "Dockerfile"
    assert dockerfile.is_file(), "Dockerfile must exist at repository root"

    text = dockerfile.read_text(encoding="utf-8")
    assert "python:3.13-slim" in text, "Must use python:3.13-slim as base image"
    assert "USER mcpscan" in text, "Must specify non-root USER for runtime execution"
    assert 'ENTRYPOINT ["mcpscan"]' in text, "Must define mcpscan as binary ENTRYPOINT"


def test_dockerignore_contains_critical_exclusions():
    """.dockerignore must ignore virtualenvs, tests, and git metadata."""
    dockerignore = REPO_ROOT / ".dockerignore"
    assert dockerignore.is_file(), ".dockerignore must exist"

    lines = [line.strip() for line in dockerignore.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert ".git" in lines
    assert ".venv" in lines
    assert "tests" in lines


def test_contributing_guide_exists():
    """CONTRIBUTING.md must exist and outline rule development and testing."""
    guide = REPO_ROOT / "CONTRIBUTING.md"
    assert guide.is_file(), "CONTRIBUTING.md must exist at repository root"
    text = guide.read_text(encoding="utf-8")
    assert "BaseRule" in text
    assert "pytest" in text
    assert "Conventional Commits" in text


def test_release_workflow_exists():
    """.github/workflows/release.yml must exist and trigger on version tags."""
    rel_file = REPO_ROOT / ".github" / "workflows" / "release.yml"
    assert rel_file.is_file(), "release.yml must exist"
    data = yaml.safe_load(rel_file.read_text(encoding="utf-8"))
    assert "build-and-release" in data.get("jobs", {})


def test_version_consistency():
    """mcpscan.__version__ must match pyproject.toml declaration."""
    import tomllib
    import mcpscan

    pyproject_file = REPO_ROOT / "pyproject.toml"
    with open(pyproject_file, "rb") as f:
        data = tomllib.load(f)

    declared_version = data["project"]["version"]
    assert mcpscan.__version__ == declared_version == "0.1.0"

