from __future__ import annotations

from types import SimpleNamespace

import pytest

from src.core.import_export.bitwarden_direct_import import BitwardenDirectImporter


def test_bitwarden_direct_import_requires_session(monkeypatch):
    importer = BitwardenDirectImporter(bw_path="bw", session=None)
    monkeypatch.setattr("src.core.import_export.bitwarden_direct_import.shutil.which", lambda _p: "/usr/bin/bw")

    with pytest.raises(RuntimeError, match="session is missing"):
        importer.require_ready()


def test_bitwarden_direct_import_converts_and_invokes_cli(monkeypatch):
    calls = []

    def fake_run(args, input=None, text=None, capture_output=None, check=None, env=None):
        calls.append((args, input, env))
        if args[:2] == ["bw", "encode"]:
            return SimpleNamespace(returncode=0, stdout="ENCODED_ITEM", stderr="")
        if args[:3] == ["bw", "create", "item"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

    monkeypatch.setattr("src.core.import_export.bitwarden_direct_import.shutil.which", lambda _p: "/usr/bin/bw")
    monkeypatch.setattr("src.core.import_export.bitwarden_direct_import.subprocess.run", fake_run)

    entry = SimpleNamespace(
        title="Example",
        username="user@example.com",
        password="secret",
        url="https://example.com",
        notes="note",
    )

    importer = BitwardenDirectImporter(bw_path="bw", session="SESSION123")
    result = importer.import_entries([entry])

    assert result.created == 1
    assert result.failed == 0
    assert calls[0][0] == ["bw", "encode"]
    assert calls[1][0] == ["bw", "create", "item", "ENCODED_ITEM"]
    assert calls[0][2]["BW_SESSION"] == "SESSION123"
