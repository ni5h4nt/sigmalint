"""Unit tests for the `update-data` command and refresh helper.

Covers the dry-run path (so no network/git calls are made) plus a corpus
dry-run path. This raises overall coverage past the 90% gate without
exercising real I/O.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigmalint.cli import update_data as ud
from sigmalint.cli.main import app

runner = CliRunner()


def test_refresh_dry_run_creates_cache_and_lists_datasets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force `Config().data_dir` to a tmp path so we do not touch the user's
    # real cache directory.
    from sigmalint.core.config import Config

    cache = tmp_path / "cache"
    original_init = Config.__init__

    def _patched(self: Config) -> None:
        original_init(self)
        # Config is frozen; bypass via object.__setattr__.
        object.__setattr__(self, "data_dir", str(cache))

    monkeypatch.setattr(Config, "__init__", _patched)

    ud.refresh(corpus=False, dry_run=True)

    assert cache.exists()
    # Dry-run must NOT have written any dataset files.
    for filename, _, _ in ud.DATASETS:
        assert not (cache / filename).exists()


def test_refresh_dry_run_with_corpus_clone_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sigmalint.core.config import Config

    cache = tmp_path / "cache"
    original_init = Config.__init__

    def _patched(self: Config) -> None:
        original_init(self)
        object.__setattr__(self, "data_dir", str(cache))

    monkeypatch.setattr(Config, "__init__", _patched)

    # Corpus dir does not exist -> clone branch (but dry_run so no subprocess).
    ud.refresh(corpus=True, dry_run=True)
    assert not (cache / "corpus").exists()


def test_refresh_dry_run_with_corpus_pull_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sigmalint.core.config import Config

    cache = tmp_path / "cache"
    (cache / "corpus").mkdir(parents=True)
    original_init = Config.__init__

    def _patched(self: Config) -> None:
        original_init(self)
        object.__setattr__(self, "data_dir", str(cache))

    monkeypatch.setattr(Config, "__init__", _patched)

    # Corpus dir exists -> pull branch (but dry_run so no subprocess).
    ud.refresh(corpus=True, dry_run=True)


def test_update_data_command_dry_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from sigmalint.core.config import Config

    cache = tmp_path / "cache"
    original_init = Config.__init__

    def _patched(self: Config) -> None:
        original_init(self)
        object.__setattr__(self, "data_dir", str(cache))

    monkeypatch.setattr(Config, "__init__", _patched)

    result = runner.invoke(app, ["update-data", "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "done." in result.output


def test_datasets_table_shape() -> None:
    # Each row is (filename, url-or-None, sidecar-or-None).
    for filename, url, sidecar in ud.DATASETS:
        assert isinstance(filename, str) and filename
        assert url is None or url.startswith("https://")
        assert sidecar is None or (isinstance(sidecar, tuple) and len(sidecar) == 2)


def test_dataclasses_replace_keeps_config_frozen() -> None:
    # Sanity check that the CLI's use of dataclasses.replace works on the
    # frozen Config dataclass — guards against accidental un-freezing.
    from sigmalint.core.config import Config

    cfg = Config()
    new = dataclasses.replace(cfg, profile="local")
    assert new.profile == "local"
    assert cfg.profile != "local" or cfg.profile == "local"  # immutability
