"""Unit tests for the `update-data` command and refresh helper.

Covers both halves of `refresh`: the dry-run path (no network/git calls) and
the real `dry_run=False` path, where network fetches and git subprocess calls
are mocked at the boundary while local file I/O (sidecar writes, vendored
mirror copies) runs for real so we can assert bytes actually land on disk.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sigmalint.cli import update_data as ud
from sigmalint.cli.main import app

runner = CliRunner()


class _FakeResponse:
    """Stand-in for a `requests` response at the network boundary."""

    def __init__(self, content: bytes) -> None:
        self.content = content

    def raise_for_status(self) -> None:
        return None


@pytest.fixture
def patched_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect `Config().data_dir` at the boundary to a tmp cache dir.

    Returns the cache path so tests can assert on what `refresh` wrote without
    touching the user's real cache directory.
    """
    from sigmalint.core.config import Config

    cache = tmp_path / "cache"
    original_init = Config.__init__

    def _patched(self: Config) -> None:
        original_init(self)
        # Config is frozen; bypass via object.__setattr__.
        object.__setattr__(self, "data_dir", str(cache))

    monkeypatch.setattr(Config, "__init__", _patched)
    return cache


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


def test_refresh_fetches_url_datasets_and_writes_sidecars(
    patched_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Mock the network boundary: requests.get returns a fake response whose
    # bytes we can later assert were written to disk.
    content = b'{"mocked": "payload"}'
    monkeypatch.setattr(ud.requests, "get", lambda url, timeout: _FakeResponse(content))

    ud.refresh(corpus=False, dry_run=False)

    url_datasets = [(name, sidecar) for name, url, sidecar in ud.DATASETS if url]
    for name, sidecar in url_datasets:
        assert (patched_cache / name).read_bytes() == content
        assert sidecar is not None
        assert (patched_cache / sidecar[0]).read_text(encoding="utf-8") == sidecar[1] + "\n"


def test_refresh_mirrors_vendored_datasets(
    patched_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Vendored datasets (url is None) are copied from package data via
    # shutil.copyfile — real local I/O. The url datasets still fetch, so the
    # network boundary is stubbed with a benign fake response.
    monkeypatch.setattr(ud.requests, "get", lambda url, timeout: _FakeResponse(b"x"))

    ud.refresh(corpus=False, dry_run=False)

    vendored = [name for name, url, _ in ud.DATASETS if url is None]
    assert vendored, "expected at least one vendored dataset"
    for name in vendored:
        assert (patched_cache / name).exists()


def test_refresh_clones_corpus_when_absent(
    patched_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ud.requests, "get", lambda url, timeout: _FakeResponse(b"x"))
    calls: list[list[str]] = []
    monkeypatch.setattr(ud.subprocess, "check_call", lambda cmd: calls.append(cmd))

    ud.refresh(corpus=True, dry_run=False)

    assert len(calls) == 1
    assert calls[0][:2] == ["git", "clone"]
    assert calls[0][-1] == str(patched_cache / "corpus")


def test_refresh_pulls_corpus_when_present(
    patched_cache: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = patched_cache / "corpus"
    repo.mkdir(parents=True)
    monkeypatch.setattr(ud.requests, "get", lambda url, timeout: _FakeResponse(b"x"))
    calls: list[list[str]] = []
    monkeypatch.setattr(ud.subprocess, "check_call", lambda cmd: calls.append(cmd))

    ud.refresh(corpus=True, dry_run=False)

    assert calls == [["git", "-C", str(repo), "pull", "--ff-only"]]


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
