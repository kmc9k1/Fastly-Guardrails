from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(autouse=True)
def isolated_tool_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    tool_home = tmp_path / '.fastly_guardrails'
    monkeypatch.setenv('FASTLY_GUARDRAILS_HOME', str(tool_home))
    yield
