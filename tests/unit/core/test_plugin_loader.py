from __future__ import annotations

from pathlib import Path

import pytest

from sigmalint.core.custom_rule import import_plugin
from sigmalint.core.errors import ConfigError


def test_import_plugin_by_module_name():
    # re is a stdlib module — guaranteed available
    import_plugin("re", config_dir=Path("."))


def test_import_plugin_by_relative_path(tmp_path: Path):
    plugin = tmp_path / "my_plugin.py"
    plugin.write_text("LOADED = True\n")
    import_plugin(f"./{plugin.name}", config_dir=tmp_path)
    # No exception means success


def test_import_plugin_missing_module_raises(tmp_path: Path):
    with pytest.raises(ConfigError, match="cannot import plugin"):
        import_plugin("no_such_module_xyz", config_dir=tmp_path)


def test_import_plugin_missing_file_raises(tmp_path: Path):
    with pytest.raises(ConfigError, match="plugin path"):
        import_plugin("./missing.py", config_dir=tmp_path)


def test_import_plugin_file_that_raises_on_import(tmp_path: Path):
    bad = tmp_path / "bad_plugin.py"
    bad.write_text("raise RuntimeError('boom')\n")
    with pytest.raises(ConfigError, match="failed to load"):
        import_plugin(f"./{bad.name}", config_dir=tmp_path)
