from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

TOOL_HOME_ENV = "FASTLY_GUARDRAILS_HOME"
DEFAULT_HOME_NAME = ".fastly_guardrails"


def tool_home() -> Path:
    return Path(os.environ.get(TOOL_HOME_ENV, str(Path.home() / DEFAULT_HOME_NAME))).expanduser().resolve()


def venv_root() -> Path:
    return tool_home() / "venv"


def workspace_root() -> Path:
    return tool_home() / "workspace"


def workspace_package_root() -> Path:
    return workspace_root() / "fastly_guardrails"


def workspace_data_dir() -> Path:
    return workspace_package_root() / "data"


def workspace_signals_path() -> Path:
    return workspace_data_dir() / "signals.json"


def workspace_tests_root() -> Path:
    return workspace_root() / "tests"


def workspace_fixtures_root() -> Path:
    return workspace_tests_root() / "fixtures"


def workspace_generated_fixtures_dir() -> Path:
    return workspace_fixtures_root() / "generated"


def workspace_manifests_dir() -> Path:
    return workspace_tests_root() / "manifests"


def workspace_named_fixture(name: str) -> Path:
    return workspace_fixtures_root() / name


def state_dir() -> Path:
    return tool_home() / "state"


def logs_dir() -> Path:
    return tool_home() / "logs"


def config_path() -> Path:
    return state_dir() / "config.json"


def receipt_path() -> Path:
    return state_dir() / "install_receipt.json"


def ensure_workspace_layout() -> None:
    for path in [
        workspace_root(),
        workspace_package_root(),
        workspace_data_dir(),
        workspace_tests_root(),
        workspace_fixtures_root(),
        workspace_generated_fixtures_dir(),
        workspace_manifests_dir(),
        state_dir(),
        logs_dir(),
    ]:
        path.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def dump_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n")


def load_config() -> Dict[str, Any]:
    return load_json(config_path(), {})
