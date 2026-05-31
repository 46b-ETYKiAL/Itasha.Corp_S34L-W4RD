"""Per-backend sign/verify tests with the platform toolchain mocked.

The load-bearing honesty contract (``sealward.backends.base``) is the subject:

* ``capability_probe`` runs credential-free and NEVER raises.
* When the platform tool is absent, ``sign`` returns a ``SKIPPED_*`` outcome —
  it NEVER fabricates ``SIGNED``.
* ``verify`` is honest about an absent tool (``SKIPPED_TOOL_ABSENT``).

Every backend's tool detection routes through ``shutil.which`` in its own
module namespace, so patching that to ``None`` deterministically forces the
tool-absent path on any OS — no real signing toolchain required.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import sealward.backends  # noqa: F401 - import wires all 5 backends
from sealward.backends.android import AndroidBackend
from sealward.backends.ios import IosBackend
from sealward.backends.linux import LinuxBackend
from sealward.backends.macos import MacosBackend
from sealward.backends.windows import WindowsBackend
from sealward.config_schema import (
    CustodyProvider,
    KeyHandleRef,
    Platform,
    SigningTarget,
    TimestampAuthority,
)
from sealward.result import SigningStatus

# (backend factory, its module name, the Platform it serves)
_BACKENDS = [
    (WindowsBackend, "sealward.backends.windows", Platform.WINDOWS),
    (MacosBackend, "sealward.backends.macos", Platform.MACOS),
    (LinuxBackend, "sealward.backends.linux", Platform.LINUX),
    (AndroidBackend, "sealward.backends.android", Platform.ANDROID),
    (IosBackend, "sealward.backends.ios", Platform.IOS),
]
_BACKEND_IDS = [p.value for *_, p in _BACKENDS]


def _patch_tool_absent(monkeypatch, module_name: str) -> None:
    """Force every backend's tool detection to report nothing on PATH."""
    import importlib

    mod = importlib.import_module(module_name)
    monkeypatch.setattr(mod.shutil, "which", lambda _tool: None)
    # macOS backend also gates on platform detection; force off-Darwin so the
    # tool-absent branch is reached regardless of the host OS.
    if hasattr(mod, "MacosBackend"):
        monkeypatch.setattr(mod.MacosBackend, "_on_macos", staticmethod(lambda: False))


def _target(platform: Platform) -> SigningTarget:
    """A synthetic signing target with a (non-secret) handle + a TSA."""
    return SigningTarget(
        platform=platform,
        artifact_glob="dist/app.bin",
        key_handle=KeyHandleRef(provider=CustodyProvider.OS_KEYCHAIN, ref="signing-identity"),
        timestamp_authorities=[TimestampAuthority(url="https://timestamp.example.test")],
    )


# --- capability_probe is credential-free and never raises --------------------


@pytest.mark.parametrize(("factory", "module_name", "platform"), _BACKENDS, ids=_BACKEND_IDS)
def test_capability_probe_never_raises_and_is_credential_free(
    monkeypatch, factory, module_name, platform
) -> None:
    """The probe runs with zero credentials and returns a well-formed report."""
    _patch_tool_absent(monkeypatch, module_name)
    report = factory().capability_probe()
    assert report.platform == platform.value
    assert report.tool_present is False
    # can_sign requires BOTH tool and credential; tool-absent ⇒ cannot sign.
    assert report.can_sign is False


@pytest.mark.parametrize(("factory", "module_name", "platform"), _BACKENDS, ids=_BACKEND_IDS)
def test_backend_identity_matches_platform(factory, module_name, platform) -> None:
    """Each backend reports the platform it serves."""
    backend = factory()
    assert backend.platform == platform.value
    assert backend.name


# --- sign returns SKIPPED_* (never SIGNED) when the tool is absent -----------


@pytest.mark.parametrize(("factory", "module_name", "platform"), _BACKENDS, ids=_BACKEND_IDS)
def test_sign_skips_when_tool_absent_never_fabricates_signed(
    monkeypatch, factory, module_name, platform
) -> None:
    """No toolchain ⇒ ``SKIPPED_TOOL_ABSENT`` with a reason — never ``SIGNED``."""
    _patch_tool_absent(monkeypatch, module_name)
    outcome = factory().sign(_target(platform))
    assert outcome.status is SigningStatus.SKIPPED_TOOL_ABSENT
    assert outcome.status is not SigningStatus.SIGNED
    assert outcome.skipped_reason
    # An honest skip never carries a passed verify verdict.
    assert outcome.verify_verdict.value != "passed"


@pytest.mark.parametrize(("factory", "module_name", "platform"), _BACKENDS, ids=_BACKEND_IDS)
def test_verify_honest_when_tool_absent(monkeypatch, factory, module_name, platform) -> None:
    """``verify`` of an absent toolchain is ``SKIPPED_TOOL_ABSENT`` — never raises."""
    _patch_tool_absent(monkeypatch, module_name)
    outcome = factory().verify(Path("dist/app.bin"))
    assert outcome.status is SigningStatus.SKIPPED_TOOL_ABSENT
    assert outcome.status is not SigningStatus.VERIFIED


# --- credential-absent path is distinct from tool-absent ---------------------


def test_sign_skips_no_credential_when_tool_present_but_handle_unusable(monkeypatch) -> None:
    """Tool present + unresolvable handle ⇒ ``SKIPPED_NO_CREDENTIAL`` (not SIGNED).

    Uses the Windows backend: force a tool to be 'present' via ``shutil.which``
    but resolve the key handle as unusable so the credential-absent branch is
    exercised. SIGNED is never reached because the handle does not resolve.
    """
    import sealward.backends.windows as win

    monkeypatch.setattr(
        win.shutil, "which", lambda tool: "/usr/bin/signtool" if tool == "signtool" else None
    )

    class _UnusableResolver:
        def resolve(self, _ref, *, profile):
            from sealward.keycustody.resolver import ResolvedHandle

            return ResolvedHandle(
                provider=CustodyProvider.OS_KEYCHAIN,
                handle="signing-identity",
                available=True,
                usable=False,
                detail="synthetic: handle not usable in test",
            )

    backend = WindowsBackend(resolver=_UnusableResolver())  # type: ignore[arg-type]
    outcome = backend.sign(_target(Platform.WINDOWS))
    assert outcome.status is SigningStatus.SKIPPED_NO_CREDENTIAL
    assert outcome.status is not SigningStatus.SIGNED


# --- outcome is raw-secret-free by construction ------------------------------


@pytest.mark.parametrize(("factory", "module_name", "platform"), _BACKENDS, ids=_BACKEND_IDS)
def test_outcome_carries_no_key_material(monkeypatch, factory, module_name, platform) -> None:
    """A skipped outcome serialises a handle/reason, never key material."""
    _patch_tool_absent(monkeypatch, module_name)
    blob = factory().sign(_target(platform)).to_json()
    assert "PRIVATE KEY" not in blob
    assert "BEGIN RSA" not in blob


# --- Windows backend: tool-present branches (honest mapping, not fabrication)-


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    import subprocess

    return subprocess.CompletedProcess(["x"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_windows_probe_reports_detected_tool(monkeypatch) -> None:
    """When signtool is on PATH the probe reports tool_present + the tool name."""
    import sealward.backends.windows as win

    monkeypatch.setattr(
        win.shutil, "which", lambda tool: "/sdk/signtool" if tool == "signtool" else None
    )
    report = WindowsBackend().capability_probe()
    assert report.tool_present is True
    assert report.tool_name == "signtool"
    # No credential queried at probe time ⇒ cannot sign yet.
    assert report.can_sign is False


def test_windows_sign_requires_timestamp_authority(monkeypatch) -> None:
    """A target with no TSA fails (un-timestamped Authenticode expires) — not SIGNED."""
    import sealward.backends.windows as win

    monkeypatch.setattr(
        win.shutil, "which", lambda tool: "/sdk/signtool" if tool == "signtool" else None
    )

    class _UsableResolver:
        def resolve(self, _ref, *, profile):
            from sealward.keycustody.resolver import ResolvedHandle

            return ResolvedHandle(
                provider=CustodyProvider.OS_KEYCHAIN, handle="id", available=True, usable=True
            )

    target = SigningTarget(
        platform=Platform.WINDOWS,
        artifact_glob="dist/app.exe",
        key_handle=KeyHandleRef(provider=CustodyProvider.OS_KEYCHAIN, ref="id"),
        timestamp_authorities=[],  # no TSA configured
    )
    outcome = WindowsBackend(resolver=_UsableResolver()).sign(target)  # type: ignore[arg-type]
    assert outcome.status is SigningStatus.FAILED
    assert outcome.status is not SigningStatus.SIGNED
    assert "timestamp" in (outcome.error or "").lower()


def test_windows_sign_signed_only_after_verify_passes(monkeypatch, tmp_path) -> None:
    """SIGNED is returned ONLY after the native verifier passes (verify-after-sign).

    The signing tool itself is mocked to report success (rc 0) for both sign and
    verify — this tests that the backend RUNS verify and gates SIGNED on its
    verdict. The backend never fabricates SIGNED; the mocked tool reports the
    outcome the backend faithfully maps.
    """
    import sealward.backends.windows as win

    artifact = tmp_path / "app.exe"
    artifact.write_bytes(b"MZ synthetic-pe")

    monkeypatch.setattr(
        win.shutil, "which", lambda tool: "/sdk/signtool" if tool == "signtool" else None
    )
    monkeypatch.setattr(win, "_run", lambda argv: _completed(0, stdout="Successfully verified"))

    class _UsableResolver:
        def resolve(self, _ref, *, profile):
            from sealward.keycustody.resolver import ResolvedHandle

            return ResolvedHandle(
                provider=CustodyProvider.OS_KEYCHAIN, handle="id", available=True, usable=True
            )

    target = SigningTarget(
        platform=Platform.WINDOWS,
        artifact_glob=str(artifact),
        key_handle=KeyHandleRef(provider=CustodyProvider.OS_KEYCHAIN, ref="id"),
        timestamp_authorities=[TimestampAuthority(url="https://timestamp.example.test")],
    )
    outcome = WindowsBackend(resolver=_UsableResolver()).sign(target)  # type: ignore[arg-type]
    assert outcome.status is SigningStatus.SIGNED
    assert outcome.verify_verdict.value == "passed"


def test_windows_sign_fails_when_verify_after_sign_fails(monkeypatch, tmp_path) -> None:
    """If the native verifier FAILS after signing, the backend returns FAILED.

    The mocked tool returns rc 0 for the sign step and rc 1 for verify. The
    backend must NOT trust its own signing step — it returns FAILED with a
    failed verdict rather than SIGNED.
    """
    import sealward.backends.windows as win

    artifact = tmp_path / "app.exe"
    artifact.write_bytes(b"MZ synthetic-pe")
    monkeypatch.setattr(
        win.shutil, "which", lambda tool: "/sdk/signtool" if tool == "signtool" else None
    )

    calls = {"n": 0}

    def _fake_run(argv):
        # First call(s) are the sign (rc 0); the verify step (contains 'verify')
        # returns rc 1 to exercise the verify-after-sign failure path.
        if "verify" in argv:
            return _completed(1, stderr="signature invalid")
        calls["n"] += 1
        return _completed(0)

    monkeypatch.setattr(win, "_run", _fake_run)

    class _UsableResolver:
        def resolve(self, _ref, *, profile):
            from sealward.keycustody.resolver import ResolvedHandle

            return ResolvedHandle(
                provider=CustodyProvider.OS_KEYCHAIN, handle="id", available=True, usable=True
            )

    target = SigningTarget(
        platform=Platform.WINDOWS,
        artifact_glob=str(artifact),
        key_handle=KeyHandleRef(provider=CustodyProvider.OS_KEYCHAIN, ref="id"),
        timestamp_authorities=[TimestampAuthority(url="https://timestamp.example.test")],
    )
    outcome = WindowsBackend(resolver=_UsableResolver()).sign(target)  # type: ignore[arg-type]
    assert outcome.status is SigningStatus.FAILED
    assert outcome.status is not SigningStatus.SIGNED
    assert outcome.verify_verdict.value == "failed"


def test_windows_verify_maps_passing_tool_to_verified(monkeypatch, tmp_path) -> None:
    """verify() maps a passing native verifier to VERIFIED (rc 0 ⇒ verified)."""
    import sealward.backends.windows as win

    artifact = tmp_path / "app.exe"
    artifact.write_bytes(b"MZ synthetic")
    monkeypatch.setattr(
        win.shutil, "which", lambda tool: "/sdk/signtool" if tool == "signtool" else None
    )
    monkeypatch.setattr(win, "_run", lambda argv: _completed(0, stdout="valid"))
    outcome = WindowsBackend().verify(artifact)
    assert outcome.status is SigningStatus.VERIFIED


def test_windows_verify_maps_failing_tool_to_failed(monkeypatch, tmp_path) -> None:
    """verify() maps a failing native verifier (rc 1) to FAILED — honest."""
    import sealward.backends.windows as win

    artifact = tmp_path / "app.exe"
    artifact.write_bytes(b"MZ synthetic")
    monkeypatch.setattr(
        win.shutil, "which", lambda tool: "/sdk/signtool" if tool == "signtool" else None
    )
    monkeypatch.setattr(win, "_run", lambda argv: _completed(1, stderr="no signature"))
    outcome = WindowsBackend().verify(artifact)
    assert outcome.status is SigningStatus.FAILED
    assert outcome.status is not SigningStatus.VERIFIED


def test_linux_probe_reports_detected_tool(monkeypatch) -> None:
    """The Linux probe reports the preferred tool when one is on PATH."""
    import sealward.backends.linux as lin

    monkeypatch.setattr(
        lin.shutil, "which", lambda tool: "/usr/bin/gpg" if tool == "gpg" else None
    )
    monkeypatch.setattr(lin, "_run", lambda argv: _completed(0, stdout="gpg (GnuPG) 2.4.0"))
    report = LinuxBackend().capability_probe()
    assert report.tool_present is True
    assert report.tool_name == "gpg"
