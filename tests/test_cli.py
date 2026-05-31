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


def test_sign_dry_run_with_usable_handle_reaches_dry_run_branch(
    tmp_path, capsys, monkeypatch
) -> None:
    """A usable handle + --dry-run reaches the dry-run branch (never SIGNED)."""
    from sealward.config_schema import CustodyProvider
    from sealward.keycustody.resolver import CustodyResolver, ResolvedHandle

    # Force the resolver to report the handle usable so dispatch reaches dry-run.
    monkeypatch.setattr(
        CustodyResolver,
        "resolve",
        lambda self, ref, *, profile: ResolvedHandle(
            provider=CustodyProvider.OS_KEYCHAIN, handle=ref.ref, available=True, usable=True
        ),
    )
    config = _write_manifest(tmp_path)
    rc = cli.main(["sign", "--config", config, "--dry-run"])
    assert rc == 0
    outcomes = json.loads(capsys.readouterr().out)
    assert outcomes
    out = outcomes[0]
    assert out["status"] != "signed"
    assert out["skipped_reason"] == "dry-run: no signature performed"
    assert out["evidence"]["dry_run"] is True


def test_sign_loads_yaml_manifest(tmp_path, capsys) -> None:
    """A YAML manifest loads via PyYAML (the .yaml/.yml config branch)."""
    pytest.importorskip("yaml")
    manifest = tmp_path / "signing.yaml"
    manifest.write_text(
        "\n".join(
            [
                "contract_version: 1",
                "profile: dev",
                "targets:",
                "  - platform: linux",
                "    artifact_glob: dist/*.bin",
                "    key_handle:",
                "      provider: os_keychain",
                "      ref: signing-identity",
                "    timestamp_authorities:",
                "      - url: https://timestamp.example.test",
            ]
        ),
        encoding="utf-8",
    )
    rc = cli.main(["sign", "--config", str(manifest)])
    assert rc == 0
    outcomes = json.loads(capsys.readouterr().out)
    assert outcomes
    for outcome in outcomes:
        assert outcome["status"] != "signed"  # no real toolchain ⇒ skipped, never fabricated


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


# --- registry double-import trap (regression) --------------------------------


def test_registry_is_canonical_not_in_cli_module() -> None:
    """The dispatch dict lives in sealward.registry, not in sealward.cli.

    Regression guard for the registry double-import trap: if the dict lived in
    ``cli.py`` it would be duplicated under ``__main__`` when invoked via
    ``python -m sealward.cli`` and ``probe`` would read an empty copy.
    """
    import sealward.registry as registry

    assert hasattr(registry, "_BACKEND_FACTORIES")
    # cli must NOT define its own table — it re-exports the registry's functions.
    assert cli.register_backend is registry.register_backend
    assert cli.get_backend is registry.get_backend
    assert cli.registered_platforms is registry.registered_platforms


def test_probe_registers_all_platforms_under_dash_m_invocation() -> None:
    """``python -m sealward.cli probe`` lists all five platforms registered.

    Runs the CLI in a fresh subprocess via ``python -m`` so cli.py loads as the
    ``__main__`` module — the exact entry point that exposed the double-import
    trap. The canonical registry must make every platform register regardless.
    """
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "sealward.cli", "probe"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    caps = json.loads(result.stdout)["capabilities"]
    assert len(caps) == 5
    assert all(c["registered"] for c in caps), result.stdout
    assert {c["platform"] for c in caps} == {p.value for p in Platform}


def test_console_script_and_dash_m_agree_on_registration() -> None:
    """The in-process entry and ``python -m sealward.cli`` agree on registration.

    Both must report all five platforms registered — the in-process path and the
    runpy ``__main__`` path read the SAME canonical registry dict.
    """
    import subprocess
    import sys

    dash_m = subprocess.run(
        [sys.executable, "-m", "sealward.cli", "probe"],
        capture_output=True,
        text=True,
        check=False,
    )
    console = subprocess.run(
        [sys.executable, "-c", "from sealward.cli import main; raise SystemExit(main(['probe']))"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert dash_m.returncode == 0 and console.returncode == 0
    dash_m_regs = {
        c["platform"]: c["registered"] for c in json.loads(dash_m.stdout)["capabilities"]
    }
    console_regs = {
        c["platform"]: c["registered"] for c in json.loads(console.stdout)["capabilities"]
    }
    assert dash_m_regs == console_regs
    assert all(dash_m_regs.values())
