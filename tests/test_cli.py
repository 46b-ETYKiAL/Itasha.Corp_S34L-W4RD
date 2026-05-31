"""CLI orchestrator tests — dispatch, probe, dry-run honesty, verify.

Asserts the orchestrator-level contract:

* ``probe`` lists all five platforms and works with ZERO credentials (after the
  backends-package wiring fires their ``register_backend`` calls).
* ``sign --dry-run`` NEVER claims ``SIGNED`` — a dry-run performs no signature.
* ``verify`` dispatches to the platform backend and reports honestly.
* The dispatch table never carries a fabricated success for an absent tool.

Backend toolchains are forced absent via ``shutil.which`` patches so the tests
are deterministic on any host OS.
"""

from __future__ import annotations

import importlib
import json

import pytest

from sealward import cli
from sealward.config_schema import Platform

_BACKEND_MODULES = [
    "sealward.backends.windows",
    "sealward.backends.macos",
    "sealward.backends.linux",
    "sealward.backends.android",
    "sealward.backends.ios",
]


@pytest.fixture(autouse=True)
def _tools_absent(monkeypatch):
    """Force every backend's toolchain absent so the CLI is host-independent."""
    cli._ensure_backends_registered()
    for name in _BACKEND_MODULES:
        mod = importlib.import_module(name)
        monkeypatch.setattr(mod.shutil, "which", lambda _tool: None)
        if hasattr(mod, "MacosBackend"):
            monkeypatch.setattr(mod.MacosBackend, "_on_macos", staticmethod(lambda: False))


# --- probe lists all five platforms credential-free --------------------------


def test_probe_lists_all_five_platforms(capsys) -> None:
    """``probe`` reports every platform as registered, with zero credentials."""
    rc = cli.main(["probe"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    caps = payload["capabilities"]
    assert len(caps) == 5
    assert {c["platform"] for c in caps} == {p.value for p in Platform}
    # Wiring assertion: every platform has a registered backend.
    assert all(c["registered"] for c in caps)
    # Credential-free: no backend claims it can sign with no creds + no tool.
    assert all(c["can_sign"] is False for c in caps)


def test_probe_single_platform(capsys) -> None:
    """``probe --platform linux`` reports just that one registered backend."""
    rc = cli.main(["probe", "--platform", "linux"])
    assert rc == 0
    caps = json.loads(capsys.readouterr().out)["capabilities"]
    assert len(caps) == 1
    assert caps[0]["platform"] == "linux"
    assert caps[0]["registered"] is True


def test_registered_platforms_after_wiring() -> None:
    """All five platforms are registered once the backends package is imported."""
    cli._ensure_backends_registered()
    assert {p.value for p in cli.registered_platforms()} == {p.value for p in Platform}


def test_get_backend_resolves_every_platform() -> None:
    """``get_backend`` returns a live backend for each platform (no dormant slot)."""
    cli._ensure_backends_registered()
    for platform in Platform:
        backend = cli.get_backend(platform)
        assert backend is not None
        assert backend.platform == platform.value


# --- sign --dry-run never claims SIGNED --------------------------------------


def _write_manifest(tmp_path) -> str:
    """Write a minimal TOML signing manifest and return its path."""
    manifest = tmp_path / "signing.toml"
    manifest.write_text(
        "\n".join(
            [
                "contract_version = 1",
                'profile = "dev"',
                "[[targets]]",
                'platform = "linux"',
                'artifact_glob = "dist/*.bin"',
                "[targets.key_handle]",
                'provider = "os_keychain"',
                'ref = "signing-identity"',
                "[[targets.timestamp_authorities]]",
                'url = "https://timestamp.example.test"',
            ]
        ),
        encoding="utf-8",
    )
    return str(manifest)


def test_sign_dry_run_never_claims_signed(tmp_path, capsys) -> None:
    """``sign --dry-run`` performs no signature and NEVER reports ``signed``."""
    config = _write_manifest(tmp_path)
    rc = cli.main(["sign", "--config", config, "--dry-run"])
    assert rc == 0
    outcomes = json.loads(capsys.readouterr().out)
    assert outcomes
    for outcome in outcomes:
        assert outcome["status"] != "signed"
        assert outcome["verify_verdict"] != "passed"


def test_sign_tool_absent_is_skip_not_failure(tmp_path, capsys) -> None:
    """A real (non-dry-run) sign with no toolchain skips — never fabricates signed."""
    config = _write_manifest(tmp_path)
    rc = cli.main(["sign", "--config", config])
    # Skips are not failures: the CLI exits 0 when every target only skipped.
    assert rc == 0
    outcomes = json.loads(capsys.readouterr().out)
    for outcome in outcomes:
        assert outcome["status"].startswith("skipped_")
        assert outcome["status"] != "signed"


# --- verify dispatch ---------------------------------------------------------


def test_verify_dispatches_and_is_honest_when_tool_absent(capsys) -> None:
    """``verify`` routes to the platform backend; absent tool ⇒ honest skip, rc 0."""
    rc = cli.main(["verify", "--platform", "windows", "--artifact", "dist/app.exe"])
    # A skip is an acceptable verify result (rc 0); a fabricated VERIFIED is not.
    assert rc == 0
    outcome = json.loads(capsys.readouterr().out)
    assert outcome["status"] != "verified"
    assert outcome["status"].startswith("skipped_")


# --- subcommand surface ------------------------------------------------------


def test_version_flag(capsys) -> None:
    """``--version`` prints the package version and exits 0."""
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert "sealward" in capsys.readouterr().out


def test_missing_subcommand_errors() -> None:
    """No subcommand is an argparse usage error (exit 2)."""
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_unsupported_config_extension_errors(tmp_path) -> None:
    """A manifest with an unsupported extension is a structured SystemExit."""
    bad = tmp_path / "manifest.txt"
    bad.write_text("nope", encoding="utf-8")
    with pytest.raises(SystemExit):
        cli.main(["sign", "--config", str(bad)])
