"""`dsar init` — the one-time config write.

The install path is one `uvx` command with nothing cloned; this removes the
last friction, the two exported variables. Small command, but it writes the
file that chooses the identity provider, so its refusals matter as much as its
success path.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from dsar.init_cmd import run_init


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    target = tmp_path / "dsarhome"
    monkeypatch.setenv("DSAR_HOME", str(target))
    return target


CLIENT = "11111111-2222-3333-4444-555555555555"
TENANT = "66666666-7777-8888-9999-aaaaaaaaaaaa"


def test_init_writes_a_config_the_loader_accepts(home: Path) -> None:
    """The whole point: after this, `dsar up` needs nothing exported."""
    from dsar.config import load_config

    assert run_init(CLIENT, TENANT) == 0
    written = json.loads((home / "config.json").read_text(encoding="utf-8"))
    assert written == {"client_id": CLIENT, "tenant_id": TENANT}

    config = load_config()
    assert config.client_id == CLIENT
    assert config.tenant_id == TENANT


def test_the_file_is_owner_only(home: Path) -> None:
    """`tenant_id` chooses which Entra tenant sign-in goes to, so whoever can
    write the file chooses the identity provider. The loader refuses a
    group-writable file; init must not create one it would then refuse."""
    if os.name != "posix":
        pytest.skip("POSIX permissions")
    run_init(CLIENT, TENANT)
    mode = stat.S_IMODE((home / "config.json").stat().st_mode)
    assert mode == 0o600, oct(mode)


def test_an_existing_config_is_not_overwritten(home: Path) -> None:
    run_init(CLIENT, TENANT)
    (home / "config.json").write_text('{"client_id": "keep", "tenant_id": "keep"}')
    assert run_init("99999999-8888-7777-6666-555555555555", TENANT) == 1
    assert "keep" in (home / "config.json").read_text()

    assert run_init("99999999-8888-7777-6666-555555555555", TENANT, force=True) == 0
    assert "keep" not in (home / "config.json").read_text()


def test_a_non_guid_is_refused_with_nothing_written(home: Path) -> None:
    """A config that cannot work is worse than none: `dsar up` would start,
    show the sign-in page, and fail at Entra with an error about an unknown
    application — three screens from the actual mistake."""
    assert run_init("not-a-guid", TENANT) == 2
    assert not (home / "config.json").exists()


def test_missing_values_fail_loudly_without_a_terminal(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A script that forgot a flag must not hang on stdin."""
    import io
    import sys

    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    with pytest.raises(SystemExit, match="required"):
        run_init("", TENANT)
