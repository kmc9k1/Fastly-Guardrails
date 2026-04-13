from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .models import Signal


def load_signals() -> List[Signal]:
    data_path = Path(__file__).resolve().parent / "data" / "signals.json"
    raw = json.loads(data_path.read_text())
    return [Signal(**item) for item in raw]
