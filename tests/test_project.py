"""Keep the packaging, the offline demo and the docs consistent with the code."""

from __future__ import annotations

import importlib.util
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_demo_html_is_up_to_date():
    spec = importlib.util.spec_from_file_location("build_demo_preview", ROOT / "scripts" / "build_demo_preview.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    html, _, _ = module.build_html()
    assert html == (ROOT / "index.html").read_text(encoding="utf-8"), "run: python scripts/build_demo_preview.py"


def test_requirements_match_pyproject_dependencies():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = sorted(pyproject["project"]["dependencies"])
    listed = sorted(
        line.strip() for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    )
    assert declared == listed


def test_demo_has_no_external_resources_and_correct_mitre_links():
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"""(?:src|href)=["']https?://(?!attack\.mitre\.org)""", html)
    assert "%2F" not in html and "encodeURIComponent(a.mitre_id" not in html
