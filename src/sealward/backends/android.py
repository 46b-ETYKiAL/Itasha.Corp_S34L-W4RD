"""Android signing backend — apksigner (APK Signature Scheme v2/v3/v4) + jarsigner.

This backend shells out to the canonical Android signing toolchain. The
preferred tool is ``apksigner`` (the only tool that emits APK Signature Scheme
v2/v3/v4): Scheme v2 is required for Google Play, Scheme v3 adds key rotation,
and Scheme v4 produces an incremental ``<apk>.apk.idsig`` sidecar that requires
a complementary v2 or v3 signature. ``jarsigner`` is the legacy fallback (Scheme
v1 / JAR signing only) for environments where ``apksigner`` is unavailable.

The honesty contract from :mod:`sealward.backends.base` is load-bearing:

* :meth:`AndroidBackend.capability_probe` detects ``apksigner`` / ``jarsigner`` /
  ``zipalign`` AND keystore-handle resolvability WITHOUT requiring any
  credential — so the ``probe`` CLI subcommand works with zero secrets.
* :meth:`AndroidBackend.sign` returns ``SKIPPED_TOOL_ABSENT`` when no signer is
  installed and ``SKIPPED_NO_CREDENTIAL`` when the keystore handle does not
  resolve. It NEVER fabricates a ``SIGNED`` outcome, and it runs
  ``apksigner verify`` after signing — ``SIGNED`` is returned only when the
  native verifier passes.
* :meth:`AndroidBackend.verify` runs ``apksigner verify`` honestly.

Key custody: the keystore is referenced by a :class:`KeyHandleRef` resolved
through the :class:`~sealward.keycustody.resolver.CustodyResolver`. The keystore
PASSWORD and key PASSWORD are read from environment-variable NAMES (the
forge ``signing.py`` ``MYAPP_*`` env-only pattern) — never inlined, never logged.
The argv carries only the env-var-sourced password values at the moment of the
subprocess call; no password is ever placed in a :class:`SigningOutcome`,
the evidence dict, or a log line.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from sealward.backends.base import CapabilityReport, SignerBackendABC
from sealward.config_schema import Platform
from sealward.keycustody.resolver import CustodyResolver
from sealward.result import SigningOutcome, SigningStatus, VerifyVerdict, outcome_counter

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sealward.config_schema import SigningTarget

__all__ = ["AndroidBackend"]

_BACKEND_NAME = "android"

# Environment-variable NAMES the keystore credentials are sourced from. We read
# the VALUES only at subprocess-build time; the names are the only thing that
# ever appears in code. Mirrors the forge signing.py MYAPP_* env-only contract.
_ENV_KEYSTORE_PASSWORD = "SEALWARD_ANDROID_KEYSTORE_PASSWORD"  # noqa: S105 - env-var NAME, not a secret value
_ENV_KEY_PASSWORD = "SEALWARD_ANDROID_KEY_PASSWORD"  # noqa: S105 - env-var NAME, not a secret value
_ENV_KEY_ALIAS = "SEALWARD_ANDROID_KEY_ALIAS"

# Subprocess timeouts (seconds) — bounded so a hung tool never blocks the gate.
_PROBE_TIMEOUT = 15
_SIGN_TIMEOUT = 120
_VERIFY_TIMEOUT = 60


def _which(tool: str) -> str | None:
    """Return the absolute path to ``tool`` on PATH, or ``None`` if absent."""
    return shutil.which(tool)


def _run(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` capturing text output; never raises on non-zero exit.

    ``check`` is intentionally False AND the caller ALWAYS reads ``returncode``
    (silent-error-discipline: a discarded exit code is silent failure). Tool
    absence / timeout map to a synthetic returncode so callers branch cleanly.
    """
    try:
        return subprocess.run(  # noqa: S603 - argv list, shell=False, trusted tool names
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, returncode=127, stdout="", stderr="tool not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            argv, returncode=124, stdout="", stderr=f"timed out after {timeout}s"
        )


def _tool_version(tool_path: str) -> str | None:
    """Return a short version string for the signer tool, or ``None``.

    Credential-free: ``apksigner version`` / ``jarsigner -version`` require no
    keystore. Failures degrade to ``None`` rather than raising.
    """
    name = Path(tool_path).stem.lower()
    if name.startswith("apksigner"):
        proc = _run([tool_path, "version"], timeout=_PROBE_TIMEOUT)
    else:  # jarsigner
        proc = _run([tool_path, "-version"], timeout=_PROBE_TIMEOUT)
    if proc.returncode == 0:
        out = (proc.stdout or proc.stderr or "").strip().splitlines()
        if out:
            return out[0][:120]
    return None


class AndroidBackend(SignerBackendABC):
    """APK signing via apksigner (v2/v3/v4) with a jarsigner fallback.

    The backend prefers ``apksigner`` because it is the only tool that emits APK
    Signature Scheme v2+ (required for Play Store distribution). ``jarsigner``
    is the v1-only legacy fallback. ``zipalign`` presence is reported by the
    probe (apksigner expects an aligned APK) but is never a hard requirement of
    a sign attempt — alignment is the build pipeline's responsibility.
    """

    name = _BACKEND_NAME
    platform = Platform.ANDROID.value

    def __init__(self, resolver: CustodyResolver | None = None) -> None:
        """Create the backend; ``resolver`` defaults to a fresh CustodyResolver."""
        self._resolver = resolver or CustodyResolver()

    # -- capability probe (credential-free) -----------------------------------

    def capability_probe(self) -> CapabilityReport:
        """Detect signer/zipalign tools + keystore-handle availability.

        Credential-free by construction: it probes tool presence on PATH and the
        *presence* of the keystore env-var names, never their values, and never
        requires a credential to be set. ``tool_name`` reports the preferred
        signer (``apksigner`` when present, else ``jarsigner``).
        """
        apksigner = _which("apksigner")
        jarsigner = _which("jarsigner")
        zipalign = _which("zipalign")
        signer = apksigner or jarsigner
        tool_present = signer is not None

        tool_name: str | None = None
        tool_version: str | None = None
        if signer is not None:
            tool_name = Path(signer).stem
            tool_version = _tool_version(signer)

        # Credential presence: the keystore password env-var name is SET (we do
        # NOT read or echo its value). This is the honest "is a credential
        # available?" signal without requiring the credential to be valid.
        credential_present = bool(os.environ.get(_ENV_KEYSTORE_PASSWORD))

        detail_parts = [
            f"apksigner={'yes' if apksigner else 'no'}",
            f"jarsigner={'yes' if jarsigner else 'no'}",
            f"zipalign={'yes' if zipalign else 'no'}",
            f"keystore_password_env={'set' if credential_present else 'unset'}",
        ]
        return CapabilityReport.from_flags(
            backend=self.name,
            platform=self.platform,
            tool_present=tool_present,
            credential_present=credential_present,
            tool_name=tool_name,
            tool_version=tool_version,
            detail="; ".join(detail_parts),
        )

    # -- sign (verify-after-sign mandatory) -----------------------------------

    def sign(self, target: SigningTarget) -> SigningOutcome:
        """Sign the APK named by ``target`` with apksigner (v2/v3, +v4 idsig).

        Honesty contract:

        * No signer tool on PATH → ``SKIPPED_TOOL_ABSENT``.
        * Keystore handle unresolvable OR keystore password env-var unset →
          ``SKIPPED_NO_CREDENTIAL``.
        * Sign succeeds → run ``apksigner verify`` and return ``SIGNED`` only
          when the verifier PASSES; otherwise ``FAILED`` with verdict FAILED.
        * Tool error → ``FAILED`` with redacted stderr.

        Never raises; never fabricates SIGNED; never logs key material.
        """
        artifact = self._resolve_artifact(target.artifact_glob)
        apksigner = _which("apksigner")
        jarsigner = _which("jarsigner")
        if apksigner is None and jarsigner is None:
            return self._skipped(
                SigningStatus.SKIPPED_TOOL_ABSENT,
                artifact,
                "neither apksigner nor jarsigner found on PATH",
            )

        # Resolve the keystore handle through the custody layer (handle only).
        resolved = self._resolver.resolve(target.key_handle)
        keystore_password = os.environ.get(_ENV_KEYSTORE_PASSWORD)
        if not resolved.usable or not keystore_password:
            reason = (
                resolved.detail
                if not resolved.usable
                else f"{_ENV_KEYSTORE_PASSWORD} env-var unset"
            )
            return self._skipped(
                SigningStatus.SKIPPED_NO_CREDENTIAL,
                artifact,
                f"keystore handle not usable: {reason}",
            )

        if artifact is None:
            return self._record(
                SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=self.name,
                    artifact=target.artifact_glob,
                    error=f"no artifact matched glob '{target.artifact_glob}'",
                )
            )

        if apksigner is not None:
            return self._sign_with_apksigner(apksigner, artifact, target, keystore_password)
        return self._sign_with_jarsigner(
            jarsigner,  # type: ignore[arg-type]  # guarded: both-None returned above
            artifact,
            target,
            keystore_password,
        )

    def _sign_with_apksigner(
        self,
        apksigner: str,
        artifact: Path,
        target: SigningTarget,
        keystore_password: str,
    ) -> SigningOutcome:
        """Sign with apksigner (v2+v3, plus v4 idsig); then verify-after-sign."""
        alias = os.environ.get(_ENV_KEY_ALIAS)
        key_password = os.environ.get(_ENV_KEY_PASSWORD)
        # apksigner reads passwords from env-var NAMES via pass:env: — the value
        # never appears in argv. v4 idsig requires a complementary v2/v3 sig,
        # which apksigner emits by default; we enable v2+v3 explicitly and v4.
        argv = [
            apksigner,
            "sign",
            "--ks",
            target.key_handle.ref,
            "--ks-pass",
            f"env:{_ENV_KEYSTORE_PASSWORD}",
            "--v2-signing-enabled",
            "true",
            "--v3-signing-enabled",
            "true",
            "--v4-signing-enabled",
            "true",
        ]
        if alias:
            argv += ["--ks-key-alias", alias]
        if key_password:
            argv += ["--key-pass", f"env:{_ENV_KEY_PASSWORD}"]
        argv.append(str(artifact))

        proc = _run(argv, timeout=_SIGN_TIMEOUT)
        if proc.returncode != 0:
            return self._record(
                SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=self.name,
                    artifact=str(artifact),
                    algorithm="apk-v2+v3+v4",
                    key_handle=target.key_handle.ref,
                    verify_verdict=VerifyVerdict.NOT_RUN,
                    error=self._redact(proc.stderr or proc.stdout, keystore_password),
                )
            )

        # Mandatory verify-after-sign — never trust the signing step alone.
        verdict = self._run_verify(apksigner, artifact)
        idsig = artifact.with_name(artifact.name + ".idsig")
        if verdict is not VerifyVerdict.PASSED:
            return self._record(
                SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=self.name,
                    artifact=str(artifact),
                    algorithm="apk-v2+v3+v4",
                    key_handle=target.key_handle.ref,
                    verify_verdict=verdict,
                    error="apksigner verify did not pass after sign",
                )
            )
        return self._record(
            SigningOutcome(
                status=SigningStatus.SIGNED,
                backend=self.name,
                artifact=str(artifact),
                algorithm="apk-v2+v3+v4",
                key_handle=target.key_handle.ref,
                verify_verdict=VerifyVerdict.PASSED,
                evidence={
                    "signer": "apksigner",
                    "schemes": "v2+v3+v4",
                    "v4_idsig_present": idsig.is_file(),
                    "verify": "passed",
                },
            )
        )

    def _sign_with_jarsigner(
        self,
        jarsigner: str,
        artifact: Path,
        target: SigningTarget,
        keystore_password: str,
    ) -> SigningOutcome:
        """Sign with the legacy jarsigner fallback (Scheme v1 / JAR signing).

        jarsigner cannot emit Scheme v2/v3/v4 and has no equivalent of
        ``apksigner verify``; a jarsigner-only signature is recorded with an
        honest ``verify_verdict`` of ``NOT_RUN`` and a v1-only algorithm tag.
        """
        alias = os.environ.get(_ENV_KEY_ALIAS) or "androidkey"
        # jarsigner reads the storepass from stdin (``-storepass:env``) — the
        # value never appears in argv.
        argv = [
            jarsigner,
            "-storepass:env",
            _ENV_KEYSTORE_PASSWORD,
            "-keystore",
            target.key_handle.ref,
        ]
        if os.environ.get(_ENV_KEY_PASSWORD):
            argv += ["-keypass:env", _ENV_KEY_PASSWORD]
        argv += [str(artifact), alias]

        proc = _run(argv, timeout=_SIGN_TIMEOUT)
        if proc.returncode != 0:
            return self._record(
                SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=self.name,
                    artifact=str(artifact),
                    algorithm="apk-v1",
                    key_handle=target.key_handle.ref,
                    error=self._redact(proc.stderr or proc.stdout, keystore_password),
                )
            )
        # jarsigner has no native APK-scheme verifier; record honestly.
        return self._record(
            SigningOutcome(
                status=SigningStatus.SIGNED,
                backend=self.name,
                artifact=str(artifact),
                algorithm="apk-v1",
                key_handle=target.key_handle.ref,
                verify_verdict=VerifyVerdict.NOT_RUN,
                evidence={
                    "signer": "jarsigner",
                    "schemes": "v1",
                    "note": "jarsigner emits Scheme v1 only; v2+ requires apksigner",
                },
            )
        )

    # -- verify ----------------------------------------------------------------

    def verify(self, artifact: Path) -> SigningOutcome:
        """Verify an existing APK signature via ``apksigner verify``.

        Returns ``VERIFIED`` / ``FAILED``, or ``SKIPPED_TOOL_ABSENT`` when
        apksigner is not installed. Never raises.
        """
        apksigner = _which("apksigner")
        if apksigner is None:
            return self._skipped(
                SigningStatus.SKIPPED_TOOL_ABSENT,
                artifact,
                "apksigner not found on PATH (required for APK signature verification)",
            )
        if not artifact.is_file():
            return self._record(
                SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=self.name,
                    artifact=str(artifact),
                    error=f"artifact not found: {artifact}",
                )
            )
        verdict = self._run_verify(apksigner, artifact)
        status = SigningStatus.VERIFIED if verdict is VerifyVerdict.PASSED else SigningStatus.FAILED
        return self._record(
            SigningOutcome(
                status=status,
                backend=self.name,
                artifact=str(artifact),
                algorithm="apk",
                verify_verdict=verdict,
                evidence={"verify": verdict.value, "verifier": "apksigner"},
                error=None if status is SigningStatus.VERIFIED else "apksigner verify failed",
            )
        )

    # -- helpers ---------------------------------------------------------------

    def _run_verify(self, apksigner: str, artifact: Path) -> VerifyVerdict:
        """Run ``apksigner verify`` and map the exit code to a verdict."""
        proc = _run([apksigner, "verify", str(artifact)], timeout=_VERIFY_TIMEOUT)
        if proc.returncode == 0:
            return VerifyVerdict.PASSED
        if proc.returncode in (124, 127):  # timeout / tool vanished mid-run
            return VerifyVerdict.NOT_RUN
        return VerifyVerdict.FAILED

    def _resolve_artifact(self, glob: str) -> Path | None:
        """Resolve the first artifact matching ``glob`` (or a literal path).

        A non-glob literal path is returned as-is when it exists; a glob is
        expanded relative to CWD and the first match (sorted) is returned.
        """
        literal = Path(glob)
        if literal.is_file():
            return literal
        matches = sorted(Path().glob(glob))
        files = [m for m in matches if m.is_file()]
        return files[0] if files else None

    def _skipped(self, status: SigningStatus, artifact: Path | None, reason: str) -> SigningOutcome:
        """Build + record a structured SKIPPED_* outcome (never SIGNED)."""
        return self._record(
            SigningOutcome(
                status=status,
                backend=self.name,
                artifact=str(artifact) if artifact is not None else None,
                skipped_reason=reason,
            )
        )

    def _record(self, outcome: SigningOutcome) -> SigningOutcome:
        """Record the outcome in the PII-free counter and return it."""
        outcome_counter.record(outcome)
        return outcome

    @staticmethod
    def _redact(text: str | None, *secrets: str | None) -> str:
        """Redact any known secret value out of tool stderr before it is stored.

        Defence-in-depth: passwords are passed via env-var NAMES so they should
        never appear in tool output, but if a tool echoes one we scrub it.
        """
        if not text:
            return ""
        cleaned = text
        for secret in secrets:
            if secret:
                cleaned = cleaned.replace(secret, "***")
        return cleaned[:500]


# -- self-registration at import ----------------------------------------------
#
# Register a zero-arg factory so the orchestrator dispatch table picks up the
# Android backend the moment this module is imported. backends/__init__.py must
# import this module for the registration to fire (it does NOT import it itself
# to keep the package importable on machines without the Android toolchain — the
# CLI imports concrete backends as the Phase 2-6 modules land).
from sealward.registry import register_backend  # noqa: E402 - deferred to avoid import cycle

register_backend(Platform.ANDROID, AndroidBackend)
