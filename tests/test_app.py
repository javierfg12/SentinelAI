"""Smoke test: every page of the Streamlit app renders without exceptions."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parents[1] / "app.py")
PAGES = ["Visión general", "Centro de alertas", "Explorador de eventos", "Detección con ML", "Reglas y metodología"]


def test_all_pages_render_with_demo_data():
    at = AppTest.from_file(APP, default_timeout=120).run()
    for page in PAGES:
        at.sidebar.radio[0].set_value(page).run()
        assert not at.exception, f"{page}: {[e.value for e in at.exception]}"
        assert not at.error, f"{page}: {[e.value for e in at.error]}"


def test_alert_description_is_rendered_as_plain_text():
    at = AppTest.from_file(APP, default_timeout=120).run()
    at.sidebar.radio[0].set_value("Centro de alertas").run()
    assert any("fallos" in t.value or "autenticaciones" in t.value or "Acceso correcto" in t.value for t in at.text)
