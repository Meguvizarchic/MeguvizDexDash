#!/usr/bin/env python3
"""Repeat the schema-only probe with a new immutable result directory."""
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("vtab_prewarm_probe", HERE / "run_probe.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.OUT = HERE / "probe2"
raise SystemExit(module.main())
