from __future__ import annotations

import os

import yaml

from .core import Finding
from .dockerfile import lint_dockerfile
from .k8s import lint_manifest

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".github"}


def _is_dockerfile(name: str) -> bool:
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile")


def lint_path(root: str) -> tuple[list[Finding], int, list[str]]:
    """Lint a file or directory. Returns (findings, files checked, files that could not be parsed)."""
    paths = [root] if os.path.isfile(root) else []
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        paths += [os.path.join(directory, f) for f in sorted(files)]
    findings, checked, errors = [], 0, []
    for path in paths:
        name = os.path.basename(path)
        shown = os.path.relpath(path, root).replace(os.sep, "/") if os.path.isdir(root) else name
        if not (_is_dockerfile(name) or name.endswith((".yaml", ".yml"))):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        if _is_dockerfile(name):
            findings += lint_dockerfile(text, shown)
            checked += 1
        else:
            try:
                findings += lint_manifest(text, shown)
                checked += 1
            except yaml.YAMLError as exc:      # e.g. Helm templates, which are not valid YAML until rendered
                errors.append(f"{shown}: {str(exc).splitlines()[0]}")
    return findings, checked, errors
