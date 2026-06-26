from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


def load_json_resource(name: str) -> Any:
    """Load a JSON file packaged under cybershell/data."""
    data_path = files("cybershell").joinpath("data").joinpath(name)
    with data_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)

