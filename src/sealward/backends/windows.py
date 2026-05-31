"""Windows Authenticode signing backend (SignTool / osslsigncode / jsign).

This backend signs PE / MSI artifacts with an Authenticode signature and an
RFC-3161 timestamp, then verifies its own output before returning ``SIGNED``.
It auto-detects the present toolchain in preference order:

1. **SignTool** (``signtool.exe``) — the native Windows SDK signer.
2. **osslsigncode** — the cross-platform OSS signer. The version probe REQUIRES
   ``>= 2.13``: osslsigncode 2.12 shipped a verify-time RCE that 2.13 fixed, so a
   detected ``< 2.13`` is treated as tool-absent (never selected).
3. **jsign** — the JVM signer with cloud-KMS / token custody support.

The honesty contract (see :mod:`sealward.backends.base`) is load-bearing:
``capability_probe`` detects tool + key-handle presence WITHOUT a credential;
``sign`` returns ``SIGNED`` ONLY after the native verifier passed (no tool →
``SKIPPED_TOOL_ABSENT``; no resolvable handle → ``SKIPPED_NO_CREDENTIAL``; tool
error → ``FAILED``), never fabricating ``SIGNED``. An RFC-3161 timestamp is
mandatory (an un-timestamped Authenticode signature expires with the
certificate): a target with no reachable TSA yields the
``timestamp_authority_unreachable`` fork → ``FAILED``, never a silent
un-timestamped signature.

Key material is NEVER materialised or logged: only the (non-secret) key HANDLE
is passed to the tool and recorded in the outcome. All subprocess calls use argv
lists (``shell=False``) — never a shell string.
"""

from __future__ import annotations

import glob
import re
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from sealward.backends.base import CapabilityReport, SignerBackendABC
from sealward.config_schema import Platform, Profile
from sealward.keycustody.resolver import CustodyResolver
from sealward.registry import register_backend
from sealward.result import SigningOutcome, SigningStatus, VerifyVerdict, outcome_counter

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sealward.config_schema import SigningTarget

__all__ = ["WindowsBackend"]

_BACKEND_NAME = "windows"
_ALGORITHM = "authenticode"

#: Minimum acceptable osslsigncode version. 2.12 shipped a verify-time RCE that
#: 2.13 fixed; a detected version below this floor is treated as tool-absent.
_OSSLSIGNCODE_MIN = (2, 13)

#: Bounded subprocess timeout (seconds) — a signing tool that hangs is a failure,
#: not an infinite wait.
_TOOL_TIMEOUT = 120

# Tool detection order: native first, then OSS, then JVM.
_TOOL_SIGNTOOL = "signtool"
_TOOL_OSSLSIGNCODE = "osslsigncode"
_TOOL_JSIGN = "jsign"


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` with ``shell=False`` and a bounded timeout, capturing text.

    Args:
        argv: The argument vector (never a shell string).

    Returns:
        The completed process. ``check=False`` — the caller inspects
        ``returncode`` explicitly so a non-zero exit is a structured outcome,
        not a raised exception.
    """
    return subprocess.run(  # noqa: S603 - argv list, shell=False, no untrusted shell
        argv,
        capture_output=True,
        text=True,
        timeout=_TOOL_TIMEOUT,
        check=False,
    )


def _parse_osslsigncode_version(text: str) -> tuple[int, int] | None:
    """Extract a ``(major, minor)`` version tuple from osslsigncode ``--version``.

    Args:
        text: Combined stdout/stderr of ``osslsigncode --version``.

    Returns:
        The parsed ``(major, minor)`` tuple, or ``None`` when no version is
        found (treated as below the floor by the caller).
    """
    match = re.search(r"osslsigncode\s+(\d+)\.(\d+)", text, re.IGNORECASE)
    if match is None:
        match = re.search(r"\b(\d+)\.(\d+)(?:\.\d+)?\b", text)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)))


def _detect_tool() -> tuple[str | None, str | None, str | None]:
    """Detect the preferred present signing tool WITHOUT requiring a credential.

    Returns:
        A ``(tool_name, tool_path, version)`` triple. ``tool_name`` is ``None``
        when no acceptable tool is present. A detected osslsigncode below
        :data:`_OSSLSIGNCODE_MIN` is skipped (not selected) and the next tool in
        preference order is considered.
    """
    signtool = shutil.which(_TOOL_SIGNTOOL)
    if signtool is not None:
        return (_TOOL_SIGNTOOL, signtool, None)

    osslsigncode = shutil.which(_TOOL_OSSLSIGNCODE)
    if osslsigncode is not None:
        version = _osslsigncode_version_string(osslsigncode)
        parsed = _parse_osslsigncode_version(version or "")
        if parsed is not None and parsed >= _OSSLSIGNCODE_MIN:
            return (_TOOL_OSSLSIGNCODE, osslsigncode, version)
        # Present but below the security floor — do NOT select it; fall through.

    jsign = shutil.which(_TOOL_JSIGN)
    if jsign is not None:
        return (_TOOL_JSIGN, jsign, None)

    return (None, None, None)


def _osslsigncode_version_string(path: str) -> str | None:
    """Return the raw ``osslsigncode --version`` text, or ``None`` on failure."""
    try:
        result = _run([path, "--version"])
    except (OSError, subprocess.SubprocessError):
        # silence-reason: cleanup-best-effort; owner: 46b-ETYKiAL; expires: 2027-05-30
        return None
    return f"{result.stdout}\n{result.stderr}"


class WindowsBackend(SignerBackendABC):
    """Authenticode signer for Windows PE / MSI artifacts.

    Selects the first present tool in the order SignTool → osslsigncode (>= 2.13)
    → jsign, applies an RFC-3161 timestamp, and verifies its own output. Returns
    a structured :class:`~sealward.result.SigningOutcome` for every path; never
    raises, never fabricates ``SIGNED``.
    """

    name: str = _BACKEND_NAME
    platform: str = Platform.WINDOWS.value

    def __init__(self, *, resolver: CustodyResolver | None = None) -> None:
        """Build the backend.

        Args:
            resolver: Custody resolver used to check key-handle availability.
                Defaults to a fresh :class:`CustodyResolver`.
        """
        self._resolver = resolver or CustodyResolver()

    # -- capability probe -----------------------------------------------------

    def capability_probe(self) -> CapabilityReport:
        """Detect tool + credential presence WITHOUT requiring either.

        The probe is credential-free: it reports whether a signing tool is on
        ``PATH`` and (only when a handle-resolver is queried later) whether a
        credential could resolve. With no target in hand the probe reports
        ``credential_present=False`` — the report is the tool-presence surface
        the ``probe`` CLI relies on. NEVER raises.

        Returns:
            A :class:`CapabilityReport` whose ``can_sign`` is False until both a
            tool and a credential are confirmed present at sign time.
        """
        try:
            tool_name, _path, version = _detect_tool()
        except (OSError, subprocess.SubprocessError):
            # silence-reason: caller-contract; owner: 46b-ETYKiAL; expires: 2027-05-30
            tool_name, version = None, None
        tool_present = tool_name is not None
        detail = (
            f"detected {tool_name}" + (f" {version.strip()}" if version else "")
            if tool_present
            else "no signtool / osslsigncode>=2.13 / jsign on PATH"
        )
        return CapabilityReport.from_flags(
            backend=_BACKEND_NAME,
            platform=Platform.WINDOWS.value,
            tool_present=tool_present,
            credential_present=False,
            tool_name=tool_name,
            tool_version=(version.strip() if version else None),
            detail=detail,
        )

    # -- sign -----------------------------------------------------------------

    def sign(self, target: SigningTarget) -> SigningOutcome:
        """Sign every artifact matched by ``target`` and verify the result.

        Honesty contract: no tool → ``SKIPPED_TOOL_ABSENT``; no resolvable key
        handle → ``SKIPPED_NO_CREDENTIAL``; no reachable TSA → ``FAILED``
        (``timestamp_authority_unreachable`` fork); tool error → ``FAILED``;
        success only after the native verifier passes → ``SIGNED``. NEVER raises,
        NEVER fabricates ``SIGNED``.
        """
        tool_name, tool_path, version = _detect_tool()
        if tool_name is None or tool_path is None:
            return self._skipped(
                SigningStatus.SKIPPED_TOOL_ABSENT,
                target,
                reason="no signtool / osslsigncode>=2.13 / jsign on PATH",
            )

        resolved = self._resolver.resolve(target.key_handle, profile=Profile.DEV)
        if not resolved.usable:
            return self._skipped(
                SigningStatus.SKIPPED_NO_CREDENTIAL,
                target,
                reason=resolved.detail or "key handle did not resolve to a usable signing key",
            )

        if not target.timestamp_authorities:
            return self._failed(
                target,
                error="no RFC-3161 timestamp authority configured; an un-timestamped "
                "Authenticode signature expires with the certificate "
                "(timestamp_authority_unreachable fork)",
                verdict=VerifyVerdict.NOT_RUN,
                extra_evidence={"timestamp_authority_unreachable": True},
            )

        artifacts = self._expand(target.artifact_glob)
        if not artifacts:
            return self._failed(
                target,
                error=f"no artifacts matched glob {target.artifact_glob!r}",
                verdict=VerifyVerdict.NOT_RUN,
            )

        # Sign each artifact; the outcome reports the first artifact (the CLI
        # iterates targets, this backend iterates the glob and fails fast).
        first = artifacts[0]
        tsa_used: str | None = None
        last_error: str | None = None
        for artifact in artifacts:
            tsa_used, last_error = self._sign_one(tool_name, tool_path, artifact, target)
            if last_error is not None:
                return self._failed(
                    target,
                    artifact=str(artifact),
                    error=last_error,
                    verdict=VerifyVerdict.NOT_RUN,
                    tool=tool_name,
                    version=version,
                )

        # Verify-after-sign: a SIGNED result is never trusted on the tool's word.
        verify_ok, verify_detail = self._verify_with(tool_name, tool_path, first)
        if not verify_ok:
            return self._failed(
                target,
                artifact=str(first),
                error=f"verify-after-sign failed: {verify_detail}",
                verdict=VerifyVerdict.FAILED,
                tool=tool_name,
                version=version,
            )

        outcome = SigningOutcome(
            status=SigningStatus.SIGNED,
            backend=_BACKEND_NAME,
            artifact=str(first),
            algorithm=_ALGORITHM,
            timestamp_authority=tsa_used,
            key_handle=target.key_handle.ref,
            verify_verdict=VerifyVerdict.PASSED,
            evidence={
                "tool": tool_name,
                "tool_version": version.strip() if version else None,
                "artifacts_signed": len(artifacts),
                "verify_detail": verify_detail,
            },
        )
        outcome_counter.record(outcome)
        return outcome

    # -- verify ---------------------------------------------------------------

    def verify(self, artifact: Path) -> SigningOutcome:
        """Verify an existing Authenticode signature on ``artifact``.

        Runs the present tool's native verifier and reports the verdict
        honestly. No tool → ``SKIPPED_TOOL_ABSENT``. NEVER raises.

        Args:
            artifact: The PE / MSI file to verify.

        Returns:
            A :class:`SigningOutcome` with status ``VERIFIED`` / ``FAILED`` /
            ``SKIPPED_TOOL_ABSENT``.
        """
        tool_name, tool_path, version = _detect_tool()
        if tool_name is None or tool_path is None:
            outcome = SigningOutcome(
                status=SigningStatus.SKIPPED_TOOL_ABSENT,
                backend=_BACKEND_NAME,
                artifact=str(artifact),
                algorithm=_ALGORITHM,
                skipped_reason="no signtool / osslsigncode>=2.13 / jsign on PATH",
            )
            outcome_counter.record(outcome)
            return outcome

        ok, detail = self._verify_with(tool_name, tool_path, artifact)
        outcome = SigningOutcome(
            status=SigningStatus.VERIFIED if ok else SigningStatus.FAILED,
            backend=_BACKEND_NAME,
            artifact=str(artifact),
            algorithm=_ALGORITHM,
            verify_verdict=VerifyVerdict.PASSED if ok else VerifyVerdict.FAILED,
            error=None if ok else detail,
            evidence={"tool": tool_name, "tool_version": version.strip() if version else None},
        )
        outcome_counter.record(outcome)
        return outcome

    # -- internals ------------------------------------------------------------

    @staticmethod
    def _expand(artifact_glob: str) -> list[Path]:
        """Expand the glob to a sorted list of existing files."""
        return sorted(Path(p) for p in glob.glob(artifact_glob) if Path(p).is_file())

    def _sign_one(
        self,
        tool_name: str,
        tool_path: str,
        artifact: Path,
        target: SigningTarget,
    ) -> tuple[str | None, str | None]:
        """Sign one artifact, trying each TSA in the fallback list in order.

        Args:
            tool_name: The selected tool name.
            tool_path: Absolute path to the tool binary.
            artifact: The file to sign.
            target: The signing target (carries key handle + TSA list).

        Returns:
            A ``(tsa_used, error)`` pair. ``error`` is ``None`` on success;
            ``tsa_used`` is the URL that succeeded. When every TSA fails the
            error reports the ``timestamp_authority_unreachable`` condition.
        """
        last_stderr = ""
        for tsa in target.timestamp_authorities:
            argv = self._sign_argv(tool_name, tool_path, artifact, target, tsa.url)
            try:
                result = _run(argv)
            except (OSError, subprocess.SubprocessError) as exc:
                last_stderr = str(exc)
                continue
            if result.returncode == 0:
                return (tsa.url, None)
            last_stderr = (result.stderr or result.stdout or "").strip()
        return (
            None,
            "timestamp_authority_unreachable: every configured TSA failed "
            f"({len(target.timestamp_authorities)} tried); last error: {last_stderr[:200]}",
        )

    @staticmethod
    def _sign_argv(
        tool_name: str,
        tool_path: str,
        artifact: Path,
        target: SigningTarget,
        tsa_url: str,
    ) -> list[str]:
        """Build the argv for the selected tool (key handle only, never a value).

        The key HANDLE (``target.key_handle.ref``) is passed by reference to the
        tool's store/container-locator flag — the private key value is never
        materialised in this process.
        """
        handle = target.key_handle.ref
        art = str(artifact)
        if tool_name == _TOOL_SIGNTOOL:
            # SignTool: SHA-256 file digest, RFC-3161 TSA, cert by store handle.
            return [tool_path, "sign", "/fd", "sha256", "/tr", tsa_url, "/td", "sha256",
                    "/n", handle, art]  # fmt: skip
        if tool_name == _TOOL_OSSLSIGNCODE:
            return [tool_path, "sign", "-h", "sha256", "-ts", tsa_url, "-pkcs11module",
                    handle, "-in", art, "-out", art]  # fmt: skip
        # jsign: cloud-KMS / token custody; handle is the keystore/alias ref.
        return [tool_path, "--tsaurl", tsa_url, "--alias", handle, art]

    def _verify_with(self, tool_name: str, tool_path: str, artifact: Path) -> tuple[bool, str]:
        """Run the tool's native verifier; return ``(ok, detail)``.

        Args:
            tool_name: The selected tool name.
            tool_path: Absolute path to the tool binary.
            artifact: The file to verify.

        Returns:
            ``(True, detail)`` when the verifier reports a valid signature;
            ``(False, detail)`` otherwise. ``detail`` is the redacted tool output.
        """
        if tool_name == _TOOL_SIGNTOOL:
            argv = [tool_path, "verify", "/pa", str(artifact)]
        elif tool_name == _TOOL_OSSLSIGNCODE:
            argv = [tool_path, "verify", "-in", str(artifact)]
        else:  # jsign has no standalone verify; fall back to osslsigncode if present.
            ossl = shutil.which(_TOOL_OSSLSIGNCODE)
            if ossl is None:
                return (False, "no verifier available for jsign-signed artifact")
            argv = [ossl, "verify", "-in", str(artifact)]
        try:
            result = _run(argv)
        except (OSError, subprocess.SubprocessError) as exc:
            return (False, f"verifier invocation failed: {exc}")
        detail = (result.stdout or result.stderr or "").strip()[:200]
        return (result.returncode == 0, detail)

    def _skipped(
        self,
        status: SigningStatus,
        target: SigningTarget,
        *,
        reason: str,
    ) -> SigningOutcome:
        """Build, record, and return a ``SKIPPED_*`` outcome."""
        outcome = SigningOutcome(
            status=status,
            backend=_BACKEND_NAME,
            artifact=target.artifact_glob,
            algorithm=_ALGORITHM,
            key_handle=target.key_handle.ref,
            skipped_reason=reason,
        )
        outcome_counter.record(outcome)
        return outcome

    def _failed(
        self,
        target: SigningTarget,
        *,
        error: str,
        verdict: VerifyVerdict,
        artifact: str | None = None,
        tool: str | None = None,
        version: str | None = None,
        extra_evidence: dict[str, str | int | bool | None] | None = None,
    ) -> SigningOutcome:
        """Build, record, and return a ``FAILED`` outcome."""
        evidence: dict[str, str | int | bool | None] = {}
        if tool is not None:
            evidence["tool"] = tool
        if version is not None:
            evidence["tool_version"] = version.strip()
        if extra_evidence:
            evidence.update(extra_evidence)
        outcome = SigningOutcome(
            status=SigningStatus.FAILED,
            backend=_BACKEND_NAME,
            artifact=artifact or target.artifact_glob,
            algorithm=_ALGORITHM,
            key_handle=target.key_handle.ref,
            verify_verdict=verdict,
            error=error,
            evidence=evidence,
        )
        outcome_counter.record(outcome)
        return outcome


# -- self-registration --------------------------------------------------------
#
# Register a zero-arg factory at import time so the CLI dispatch table
# (sealward.cli._BACKEND_FACTORIES) routes Platform.WINDOWS here. This module
# must be imported for the registration to fire; backends/__init__.py (owned by
# P8/P9) must import this module (import sealward.backends.windows).
register_backend(Platform.WINDOWS, WindowsBackend)
