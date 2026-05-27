"""
config_loader.py — Load :class:`~models.OptimizationConfig` from JSON.

The loader accepts a path to a JSON file whose keys map directly to the
fields of :class:`~models.OptimizationConfig`.  Unknown keys are silently
ignored so that partial config files work without error.

Usage
-----
::

    from edge_iot_optimizer.config_loader import load_config

    cfg = load_config("config/default_config.json")
"""

from __future__ import annotations

import json
import dataclasses
from pathlib import Path

from edge_iot_optimizer.models import OptimizationConfig


def load_config(path: str | Path) -> OptimizationConfig:
    """Load an :class:`~models.OptimizationConfig` from a JSON file.

    Parameters
    ----------
    path : str or Path
        Path to the JSON configuration file.

    Returns
    -------
    OptimizationConfig
        Populated configuration object.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    json.JSONDecodeError
        If the file is not valid JSON.
    TypeError
        If a JSON value has the wrong type for the target field.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as fh:
        data: dict = json.load(fh)

    # Only pass keys that are valid fields of OptimizationConfig
    valid_fields = {f.name for f in dataclasses.fields(OptimizationConfig)}
    filtered = {k: v for k, v in data.items() if k in valid_fields}

    return OptimizationConfig(**filtered)


def default_config() -> OptimizationConfig:
    """Return a default :class:`~models.OptimizationConfig` with safe values.

    Useful when no config file is available (e.g. during unit testing).

    Returns
    -------
    OptimizationConfig
    """
    return OptimizationConfig()
