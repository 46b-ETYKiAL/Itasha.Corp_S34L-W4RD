"""macOS signing backend — codesign + notarytool + stapler (handles only).

This backend signs macOS artifacts with the canonical Apple toolchain:

1. ``codesign`` with the Developer ID identity and Hardened Runtime
   (``--options runtime``) — the identity is resolved from a custody HANDLE
   (an OS-keychain item name / cloud-HSM handle), NEVER from inline key bytes.
2. ``xcrun notarytool submit --wait`` against an App-Store-Connect notarization
   profile (a profile NAME stored in the keychain, never a credential value).
3. ``xcrun stapler staple`` to attach the notarization ticket to the artifact.
4. Verify-after-sign that asserts **both** Gatekeeper assessment
   (``spctl --assess``) **and** ``stapler validate`` under Hardened Runtime.

The verify verdict is **load-bearing**: a failed ``spctl`` / ``stapler validate``
surfaces as ``FAILED`` — it is NEVER swallowed with ``|| true`` and a ``SIGNED``
status is never returned on a failed assessment. This is the exact bug the
plan's reviewer flagged in the installer.

Honesty primitives (per :mod:`sealward.backends.base`):

* :meth:`MacosBackend.capability_probe` is credential-free — it detects the
  toolchain (``codesign`` / ``xcrun notarytool``), a Developer-ID identity, and
  the availability of a notarization profile / key handle WITHOUT requiring any
  of them to be present.
* :meth:`MacosBackend.sign` returns ``SIGNED`` only on a real, verified
  signature. It returns ``SKIPPED_TOOL_ABSENT`` (not on macOS / no ``codesign``)
  or ``SKIPPED_NO_CREDENTIAL`` (no Developer-ID identity, or — in the prod
  profile — no notarization credential) instead of ever fabricating success.

No key material is ever logged: the backend handles only identity handles and
profile names. No LLM/vendor SDK is imported; all toolchain access is via
``subprocess`` with argv lists (never ``shell=True``).
"""

from __future__ import annotations

import platform as _platform
import shutil
import subprocess
from typing import TYPE_CHECKING

from sealward.backends.base import CapabilityReport, SignerBackendABC
from sealward.config_schema import CustodyProvider, Platform, Profile
from sealward.keycustody.resolver import CustodyResolver
from sealward.result import SigningOutcome, SigningStatus, VerifyVerdict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pathlib import Path

    from sealward.config_schema import SigningTarget

__all__ = ["MacosBackend"]

_BACKEND_NAME = "macos"
_ALGORITHM = "codesign-hardened-runtime"
_SUBPROCESS_TIMEOUT = 1800  # notarytool --wait can take many minutes; bound it anyway.


def _run(argv: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` capturing output; never raises, never uses a shell.

    The return code is ALWAYS read by the caller and made load-bearing — this
    helper deliberately does not raise so the backend can map every outcome to a
    structured :class:`~sealward.result.SigningOutcome`.
    """
    return subprocess.run(  # noqa: S603 - argv list, shell=False, no untrusted input
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _redact(text: str | None) -> str | None:
    """Trim tool output to a short, non-secret diagnostic tail.

    notarytool / codesign output can echo profile names and request IDs but
    never key bytes; we still cap length so a stray secret-shaped token cannot
    bloat a log line. Returns at most the last 500 characters.
    """
    if not text:
        return None
    stripped = text.strip()
    return stripped[-500:] if len(stripped) > 500 else stripped


class MacosBackend(SignerBackendABC):
    """Developer-ID code-signing backend for macOS artifacts.

    Implements the :class:`~sealward.backends.base.SignerBackend` Protocol via
    :class:`~sealward.backends.base.SignerBackendABC`. Shells out to the Apple
    toolchain with argv lists; returns structured outcomes for every path.
    """

    name = _BACKEND_NAME
    platform = Platform.MACOS.value

    def __init__(self) -> None:
        self._resolver = CustodyResolver()

    # --- capability probe (credential-free) ----------------------------------

    @staticmethod
    def _on_macos() -> bool:
        return _platform.system() == "Darwin"

    @staticmethod
    def _tool_version(tool: str) -> str | None:
        """Best-effort non-secret version probe (never raises)."""
        try:
            if tool == "codesign":
                proc = _run(["codesign", "--version"], timeout=15)
            else:  # xcrun notarytool
                proc = _run(["xcrun", "notarytool", "--version"], timeout=15)
        except (OSError, subprocess.SubprocessError):
            return None
        out = (proc.stdout or proc.stderr or "").strip()
        return out.splitlines()[0] if out else None

    @staticmethod
    def _has_developer_id_identity() -> bool:
        """Detect a Developer-ID code-signing identity WITHOUT requiring one.

        Uses ``security find-identity -v -p codesigning``; presence of a
        "Developer ID Application" identity means a usable cert exists. Returns
        False (never raises) when ``security`` is absent or no identity matches.
        """
        if shutil.which("security") is None:
            return False
        try:
            proc = _run(["security", "find-identity", "-v", "-p", "codesigning"], timeout=15)
        except (OSError, subprocess.SubprocessError):
            return False
        return "Developer ID Application" in (proc.stdout or "")

    def capability_probe(self) -> CapabilityReport:
        """Detect toolchain + credential presence without requiring either."""
        if not self._on_macos():
            return CapabilityReport.from_flags(
                backend=_BACKEND_NAME,
                platform=Platform.MACOS.value,
                tool_present=False,
                credential_present=False,
                detail="not running on macOS (codesign/notarytool are Darwin-only)",
            )

        codesign = shutil.which("codesign")
        # notarytool ships inside the Xcode/CLT toolchain, invoked via `xcrun`.
        xcrun = shutil.which("xcrun")
        tool_present = codesign is not None and xcrun is not None
        tool_name = "codesign+notarytool" if tool_present else (codesign and "codesign") or None
        tool_version = self._tool_version("codesign") if codesign else None

        identity_present = self._has_developer_id_identity()
        # notarytool credential availability is probed without consuming a
        # credential: we report whether the notarytool subcommand is reachable.
        notary_reachable = False
        if xcrun is not None:
            try:
                _help = _run(["xcrun", "notarytool", "--help"], timeout=15)
                notary_reachable = _help.returncode == 0
            except (OSError, subprocess.SubprocessError):
                notary_reachable = False

        if not tool_present:
            detail = "codesign and/or xcrun (notarytool/stapler) not on PATH"
        elif not identity_present:
            detail = "no Developer ID Application identity in the keychain"
        elif not notary_reachable:
            detail = "notarytool subcommand unreachable (Xcode CLT may be incomplete)"
        else:
            detail = "codesign + Developer-ID identity + notarytool present"

        return CapabilityReport.from_flags(
            backend=_BACKEND_NAME,
            platform=Platform.MACOS.value,
            tool_present=tool_present,
            tool_name=tool_name,
            tool_version=tool_version,
            credential_present=identity_present,
            detail=detail,
        )

    # --- sign -----------------------------------------------------------------

    def _skipped_tool_absent(self, target: SigningTarget, reason: str) -> SigningOutcome:
        return SigningOutcome(
            status=SigningStatus.SKIPPED_TOOL_ABSENT,
            backend=_BACKEND_NAME,
            artifact=target.artifact_glob,
            algorithm=_ALGORITHM,
            skipped_reason=reason,
        )

    def sign(self, target: SigningTarget) -> SigningOutcome:
        """codesign → notarytool → stapler → verify. SIGNED only on real success."""
        if not self._on_macos() or shutil.which("codesign") is None:
            return self._skipped_tool_absent(
                target, "codesign not available (not on macOS or Xcode CLT absent)"
            )
        if shutil.which("xcrun") is None:
            return self._skipped_tool_absent(target, "xcrun (notarytool/stapler) not on PATH")

        # Resolve the identity HANDLE (never key bytes). The prod profile rejects
        # a LOCAL_FILE handle in the resolver (CA/B CSC-17); dev permits ad-hoc.
        resolved = self._resolver.resolve(target.key_handle, profile=Profile.DEV)
        is_dev_local = target.key_handle.provider is CustodyProvider.LOCAL_FILE

        if not resolved.usable and not is_dev_local:
            return SigningOutcome(
                status=SigningStatus.SKIPPED_NO_CREDENTIAL,
                backend=_BACKEND_NAME,
                artifact=target.artifact_glob,
                algorithm=_ALGORITHM,
                key_handle=resolved.handle,
                skipped_reason=resolved.detail or "Developer ID identity handle not usable",
            )

        artifact = target.artifact_glob
        identity = resolved.handle

        # 1) codesign with Hardened Runtime. Dev + LOCAL_FILE → ad-hoc sign (no
        #    Developer-ID identity required) and no notarization; this is the
        #    dev_prod_isolation fork: ad-hoc is dev-only and never claims notarized.
        ad_hoc = is_dev_local and not self._has_developer_id_identity()
        codesign_argv = ["codesign", "--force", "--timestamp", "--options", "runtime"]
        if ad_hoc:
            codesign_argv += ["--sign", "-"]  # "-" is the ad-hoc identity
        else:
            codesign_argv += ["--sign", identity]
        codesign_argv.append(artifact)

        cs = _run(codesign_argv, timeout=300)
        if cs.returncode != 0:
            return SigningOutcome(
                status=SigningStatus.FAILED,
                backend=_BACKEND_NAME,
                artifact=artifact,
                algorithm=_ALGORITHM,
                key_handle=identity,
                verify_verdict=VerifyVerdict.FAILED,
                error=_redact(cs.stderr) or "codesign failed",
            )

        # 2) Notarize (prod / real Developer-ID path only). Ad-hoc dev signs are
        #    never notarized — and never claim to be.
        notarized = False
        notary_profile = target.notarization_profile
        if not ad_hoc:
            if not notary_profile:
                # A real Developer-ID sign that cannot notarize is NOT a verified
                # distributable signature. Honest: notarization_credential_missing.
                return SigningOutcome(
                    status=SigningStatus.SKIPPED_NO_CREDENTIAL,
                    backend=_BACKEND_NAME,
                    artifact=artifact,
                    algorithm=_ALGORITHM,
                    key_handle=identity,
                    verify_verdict=VerifyVerdict.NOT_RUN,
                    skipped_reason=(
                        "notarization_credential_missing: no notarization_profile set; "
                        "Developer-ID artifacts require notarytool credentials"
                    ),
                    evidence={"codesigned": True, "notarized": False},
                )
            notary_argv = [
                "xcrun",
                "notarytool",
                "submit",
                artifact,
                "--keychain-profile",
                notary_profile,
                "--wait",
            ]
            nt = _run(notary_argv, timeout=_SUBPROCESS_TIMEOUT)
            if nt.returncode != 0 or "status: Accepted" not in (nt.stdout or ""):
                return SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=_BACKEND_NAME,
                    artifact=artifact,
                    algorithm=_ALGORITHM,
                    key_handle=identity,
                    verify_verdict=VerifyVerdict.FAILED,
                    error=_redact(nt.stdout or nt.stderr) or "notarytool submit not Accepted",
                    evidence={"codesigned": True, "notarized": False},
                )

            # 3) Staple the notarization ticket.
            staple = _run(["xcrun", "stapler", "staple", artifact], timeout=120)
            if staple.returncode != 0:
                return SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=_BACKEND_NAME,
                    artifact=artifact,
                    algorithm=_ALGORITHM,
                    key_handle=identity,
                    verify_verdict=VerifyVerdict.FAILED,
                    error=_redact(staple.stderr) or "stapler staple failed",
                    evidence={"codesigned": True, "notarized": True, "stapled": False},
                )
            notarized = True

        # 4) Verify-after-sign (LOAD-BEARING). The verdict gates the SIGNED
        #    status; a failed assessment is NEVER swallowed.
        verify_outcome = self.verify(artifact)  # type: ignore[arg-type]
        passed = verify_outcome.verify_verdict is VerifyVerdict.PASSED

        return SigningOutcome(
            status=SigningStatus.SIGNED if passed else SigningStatus.FAILED,
            backend=_BACKEND_NAME,
            artifact=artifact,
            algorithm=_ALGORITHM,
            timestamp_authority="apple-rfc3161" if not ad_hoc else None,
            key_handle=identity,
            verify_verdict=verify_outcome.verify_verdict,
            error=None if passed else (verify_outcome.error or "verify-after-sign failed"),
            evidence={
                "codesigned": True,
                "ad_hoc": ad_hoc,
                "notarized": notarized,
                "spctl_assess": bool(verify_outcome.evidence.get("spctl_assess")),
                "stapler_validate": bool(verify_outcome.evidence.get("stapler_validate")),
            },
        )

    # --- verify ---------------------------------------------------------------

    def verify(self, artifact: Path) -> SigningOutcome:
        """Verify a signature: asserts BOTH spctl --assess AND stapler validate.

        Both checks are load-bearing. A failed Gatekeeper assessment or a failed
        stapler validation yields ``FAILED`` with ``verify_verdict=FAILED`` — the
        verdict is NEVER swallowed with ``|| true``.
        """
        artifact_str = str(artifact)
        if not self._on_macos() or shutil.which("codesign") is None:
            return SigningOutcome(
                status=SigningStatus.SKIPPED_TOOL_ABSENT,
                backend=_BACKEND_NAME,
                artifact=artifact_str,
                verify_verdict=VerifyVerdict.NOT_RUN,
                skipped_reason="codesign not available (not on macOS or Xcode CLT absent)",
            )

        # codesign structural verification under Hardened Runtime.
        cs = _run(["codesign", "--verify", "--strict", "--verbose=2", artifact_str], timeout=120)
        # Gatekeeper assessment — the load-bearing distribution gate.
        spctl = _run(
            ["spctl", "--assess", "--type", "execute", "--verbose=2", artifact_str], timeout=120
        )
        # Stapler ticket validation — load-bearing, no `|| true` swallow.
        stapler_present = shutil.which("xcrun") is not None
        if stapler_present:
            staple = _run(["xcrun", "stapler", "validate", artifact_str], timeout=120)
            stapler_ok = staple.returncode == 0
            stapler_err = _redact(staple.stderr)
        else:
            stapler_ok = False
            stapler_err = "xcrun (stapler) not on PATH"

        codesign_ok = cs.returncode == 0
        spctl_ok = spctl.returncode == 0
        all_ok = codesign_ok and spctl_ok and stapler_ok

        if all_ok:
            return SigningOutcome(
                status=SigningStatus.VERIFIED,
                backend=_BACKEND_NAME,
                artifact=artifact_str,
                algorithm=_ALGORITHM,
                verify_verdict=VerifyVerdict.PASSED,
                evidence={
                    "codesign_verify": True,
                    "spctl_assess": True,
                    "stapler_validate": True,
                },
            )

        errors = []
        if not codesign_ok:
            errors.append(f"codesign --verify: {_redact(cs.stderr) or 'failed'}")
        if not spctl_ok:
            errors.append(f"spctl --assess: {_redact(spctl.stderr) or 'rejected'}")
        if not stapler_ok:
            errors.append(f"stapler validate: {stapler_err or 'failed'}")
        return SigningOutcome(
            status=SigningStatus.FAILED,
            backend=_BACKEND_NAME,
            artifact=artifact_str,
            algorithm=_ALGORITHM,
            verify_verdict=VerifyVerdict.FAILED,
            error="; ".join(errors),
            evidence={
                "codesign_verify": codesign_ok,
                "spctl_assess": spctl_ok,
                "stapler_validate": stapler_ok,
            },
        )


# --- self-registration -------------------------------------------------------
#
# Register the factory at import time. The orchestrator (sealward.cli) routes
# Platform.MACOS → MacosBackend purely through this registration; backends/__init__
# must import this module for the registration to fire (the __init__ does not
# auto-import platform backends to keep import-on-non-Darwin cost zero).
from sealward.registry import register_backend  # noqa: E402 - deferred to avoid import cycle at top

register_backend(Platform.MACOS, MacosBackend)
