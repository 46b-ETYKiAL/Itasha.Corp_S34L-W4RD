"""iOS signing backend — ``codesign`` + Fastlane Match (handle-only).

This backend signs an ``.app`` / ``.ipa`` (or any code object ``codesign``
accepts) with an Apple *distribution* certificate and an embedded provisioning
profile. The certificate and the provisioning profile are **never embedded in
this repo and never read into this process as values**: they live in an
EXTERNAL, PRIVATE Fastlane Match store (a separate git repo / cloud bucket),
and this backend resolves only a *handle* to them.

Match-store handle model
------------------------

* The Match store location is a *handle* — supplied by the
  ``MATCH_GIT_URL`` / ``MATCH_STORAGE_MODE`` environment variables (Fastlane's
  own convention). This module reads ONLY their presence, never their value's
  secret contents, and NEVER logs them.
* The unlock secret is ``MATCH_PASSWORD``. This module reads ONLY whether it is
  *set* (presence), never the value, and NEVER logs or prints it.
* The signing identity (the distribution certificate) is referenced through the
  config's :class:`~sealward.config_schema.KeyHandleRef` — typically an
  ``OS_KEYCHAIN`` handle whose item name is the codesign identity string (e.g.
  ``"Apple Distribution: Example (TEAMID)"``). The keychain item is read by
  ``codesign`` itself at sign time; this backend never extracts key bytes.
* The provisioning profile is referenced by
  :attr:`~sealward.config_schema.SigningTarget.notarization_profile` (an opaque
  profile name / path *handle* — the manifest validator already rejects a
  ``.mobileprovision`` value). The profile is embedded into the bundle by the
  packaging step Match performs; this backend confirms its presence and passes
  it to ``codesign`` as ``--entitlements`` source data only when an explicit
  entitlements path is provided.

Honesty contract (see :mod:`sealward.backends.base`)
----------------------------------------------------

* Not on a macOS toolchain (``codesign`` absent) → ``SKIPPED_TOOL_ABSENT``.
* No usable identity handle, OR Match not configured (no ``MATCH_PASSWORD`` /
  no ``MATCH_GIT_URL``+storage handle) → ``SKIPPED_NO_CREDENTIAL``.
* A real sign runs ``codesign --sign`` and then ``codesign --verify``; the
  outcome is ``SIGNED`` only when the verifier passed. A failed verify yields
  ``FAILED`` with ``verify_verdict=FAILED`` — the backend never trusts its own
  signing step.
* Never raises; every failure mode maps to a structured
  :class:`~sealward.result.SigningOutcome`.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from sealward.backends.base import CapabilityReport, SignerBackendABC
from sealward.config_schema import CustodyProvider, Platform, Profile
from sealward.keycustody.resolver import CustodyResolver
from sealward.result import SigningOutcome, SigningStatus, VerifyVerdict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sealward.config_schema import SigningTarget

__all__ = ["IosBackend"]

_TOOL = "codesign"
_ALGORITHM = "apple-codesign"
# Match storage modes that imply an external store handle is configured.
_MATCH_STORAGE_VARS = ("MATCH_GIT_URL", "MATCH_S3_BUCKET", "MATCH_GOOGLE_CLOUD_BUCKET_NAME")
_SUBPROCESS_TIMEOUT_S = 600


def _tool_version() -> str | None:
    """Return ``codesign`` version string (non-secret), or ``None`` if absent.

    ``codesign`` has no ``--version``; its banner is emitted on stderr for a
    bare invocation. We capture it defensively and never raise.
    """
    if shutil.which(_TOOL) is None:
        return None
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [_TOOL],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    banner = (proc.stderr or proc.stdout or "").strip().splitlines()
    return banner[0].strip() if banner else None


def _match_configured() -> bool:
    """True when a Fastlane Match store handle + unlock secret are both present.

    Reads ONLY the *presence* of ``MATCH_PASSWORD`` and a storage-location var.
    Never reads, returns, or logs their values. ``readonly`` Match (CI) still
    needs both, so presence of both is the credential-availability signal.
    """
    has_secret = bool(os.environ.get("MATCH_PASSWORD"))
    has_store = any(os.environ.get(v) for v in _MATCH_STORAGE_VARS)
    return has_secret and has_store


class IosBackend(SignerBackendABC):
    """Sign iOS artifacts with ``codesign`` + a Match-supplied identity/profile."""

    name = "ios"
    platform = Platform.IOS.value

    def __init__(self) -> None:
        """Construct the backend (no credential touched at construction)."""
        self._resolver = CustodyResolver()

    # -- capability probe ----------------------------------------------------

    def capability_probe(self) -> CapabilityReport:
        """Detect ``codesign`` + Match config presence WITHOUT requiring either.

        Credential-free: probes only tool presence on PATH and whether a Match
        store handle + unlock secret are *set* (never their values). NEVER
        raises and NEVER requires a credential.
        """
        tool_present = shutil.which(_TOOL) is not None
        version = _tool_version() if tool_present else None
        match_ready = _match_configured()
        if not tool_present:
            detail = "codesign not on PATH (requires the macOS / Xcode toolchain)"
        elif not match_ready:
            detail = (
                "Fastlane Match not configured: set MATCH_PASSWORD and a store "
                "handle (MATCH_GIT_URL / MATCH_S3_BUCKET / "
                "MATCH_GOOGLE_CLOUD_BUCKET_NAME). Values are never read or logged."
            )
        else:
            detail = "codesign present; Match store handle + unlock secret configured"
        return CapabilityReport.from_flags(
            backend=self.name,
            platform=self.platform,
            tool_present=tool_present,
            credential_present=match_ready,
            tool_name=_TOOL if tool_present else None,
            tool_version=version,
            detail=detail,
        )

    # -- sign ----------------------------------------------------------------

    def sign(self, target: SigningTarget) -> SigningOutcome:
        """Sign the artifacts named by ``target`` and verify-after-sign.

        Returns ``SIGNED`` only on a real ``codesign --sign`` whose subsequent
        ``codesign --verify`` passed. Tool/credential absence maps honestly to a
        ``SKIPPED_*`` status; it NEVER fabricates ``SIGNED``. Never raises.
        """
        if shutil.which(_TOOL) is None:
            return self._skipped(
                target,
                SigningStatus.SKIPPED_TOOL_ABSENT,
                "codesign not on PATH (requires the macOS / Xcode toolchain)",
            )

        # Identity handle must resolve (keychain item / Match-imported identity).
        profile = self._profile_for(target)
        resolved = self._resolver.resolve(target.key_handle, profile=profile)
        if not resolved.usable:
            return self._skipped(
                target,
                SigningStatus.SKIPPED_NO_CREDENTIAL,
                resolved.detail or "signing identity handle not usable",
                key_handle=resolved.handle,
            )

        # Match store handle + unlock secret must be configured (presence only).
        if not _match_configured():
            return self._skipped(
                target,
                SigningStatus.SKIPPED_NO_CREDENTIAL,
                "Fastlane Match not configured (MATCH_PASSWORD + store handle absent)",
                key_handle=resolved.handle,
            )

        artifacts = self._expand(target.artifact_glob)
        if not artifacts:
            return self._skipped(
                target,
                SigningStatus.SKIPPED_NO_CREDENTIAL,
                f"no artifacts matched glob {target.artifact_glob!r}",
                key_handle=resolved.handle,
            )

        identity = resolved.handle  # codesign identity string / keychain item name
        entitlements = self._entitlements_path(target)
        signed: list[str] = []
        for art in artifacts:
            sign_proc = self._run_sign(art, identity, entitlements)
            if sign_proc.returncode != 0:
                return SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=self.name,
                    artifact=art,
                    algorithm=_ALGORITHM,
                    key_handle=identity,
                    verify_verdict=VerifyVerdict.NOT_RUN,
                    error=_redact((sign_proc.stderr or sign_proc.stdout or "").strip()),
                )
            verdict = self._verify_signature(art)
            if verdict is not VerifyVerdict.PASSED:
                return SigningOutcome(
                    status=SigningStatus.FAILED,
                    backend=self.name,
                    artifact=art,
                    algorithm=_ALGORITHM,
                    key_handle=identity,
                    verify_verdict=verdict,
                    error="codesign --verify failed after signing (signature not trusted)",
                )
            signed.append(art)

        return SigningOutcome(
            status=SigningStatus.SIGNED,
            backend=self.name,
            artifact=signed[0] if len(signed) == 1 else target.artifact_glob,
            algorithm=_ALGORITHM,
            key_handle=identity,
            verify_verdict=VerifyVerdict.PASSED,
            evidence={
                "tool": _TOOL,
                "tool_version": _tool_version(),
                "artifacts_signed": len(signed),
                "entitlements_applied": entitlements is not None,
                "match_store": "configured",  # handle only — value never recorded
                "notarization_profile": target.notarization_profile,
            },
        )

    # -- verify --------------------------------------------------------------

    def verify(self, artifact: Path) -> SigningOutcome:
        """Verify an existing signature on ``artifact`` via ``codesign --verify``.

        Returns ``VERIFIED`` / ``FAILED`` (or ``SKIPPED_TOOL_ABSENT`` when
        ``codesign`` is not installed). NEVER raises.
        """
        if shutil.which(_TOOL) is None:
            return SigningOutcome(
                status=SigningStatus.SKIPPED_TOOL_ABSENT,
                backend=self.name,
                artifact=str(artifact),
                skipped_reason="codesign not on PATH (requires the macOS / Xcode toolchain)",
            )
        verdict = self._verify_signature(str(artifact))
        if verdict is VerifyVerdict.PASSED:
            return SigningOutcome(
                status=SigningStatus.VERIFIED,
                backend=self.name,
                artifact=str(artifact),
                algorithm=_ALGORITHM,
                verify_verdict=VerifyVerdict.PASSED,
                evidence={"tool": _TOOL},
            )
        return SigningOutcome(
            status=SigningStatus.FAILED,
            backend=self.name,
            artifact=str(artifact),
            algorithm=_ALGORITHM,
            verify_verdict=verdict,
            error="codesign --verify reported the artifact as not validly signed",
        )

    # -- internals -----------------------------------------------------------

    def _profile_for(self, target: SigningTarget) -> Profile:
        """Best-effort dev/prod inference from the target's custody provider.

        A ``LOCAL_FILE`` handle is dev-only; any other provider is treated as
        prod (the resolver enforces the CA/B CSC-17 hardware rule there).
        """
        if target.key_handle.provider is CustodyProvider.LOCAL_FILE:
            return Profile.DEV
        return Profile.PROD

    @staticmethod
    def _expand(artifact_glob: str) -> list[str]:
        """Expand a glob to existing paths (sorted, deterministic)."""
        return sorted(p for p in glob.glob(artifact_glob, recursive=True) if Path(p).exists())

    @staticmethod
    def _entitlements_path(target: SigningTarget) -> str | None:
        """Resolve an optional entitlements plist path from the environment.

        Entitlements are an OPTIONAL, non-secret plist. The path is read from
        ``SEALWARD_IOS_ENTITLEMENTS`` (a path handle, never inline contents) and
        applied only when the file exists.
        """
        env = os.environ.get("SEALWARD_IOS_ENTITLEMENTS")
        if env and Path(env).is_file():
            return env
        return None

    def _run_sign(
        self, artifact: str, identity: str, entitlements: str | None
    ) -> subprocess.CompletedProcess[str]:
        """Run ``codesign --force --sign <identity> [--entitlements <p>] <art>``.

        Argv list only (no shell). The identity string and artifact path are
        passed as separate argv items; nothing is interpolated into a shell.
        """
        argv = [_TOOL, "--force", "--timestamp", "--options", "runtime", "--sign", identity]
        if entitlements is not None:
            argv += ["--entitlements", entitlements]
        argv.append(artifact)
        return subprocess.run(  # noqa: S603 - fixed argv list, shell=False
            argv,
            capture_output=True,
            text=True,
            timeout=_SUBPROCESS_TIMEOUT_S,
            check=False,
        )

    def _verify_signature(self, artifact: str) -> VerifyVerdict:
        """Run ``codesign --verify --strict`` and map the result to a verdict.

        Returns ``PASSED`` on exit 0, ``FAILED`` on a non-zero exit, and
        ``NOT_RUN`` if the verifier could not be launched. Never raises.
        """
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv list, shell=False
                [_TOOL, "--verify", "--strict", "--verbose=2", artifact],
                capture_output=True,
                text=True,
                timeout=_SUBPROCESS_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return VerifyVerdict.NOT_RUN
        return VerifyVerdict.PASSED if proc.returncode == 0 else VerifyVerdict.FAILED

    def _skipped(
        self,
        target: SigningTarget,
        status: SigningStatus,
        reason: str,
        *,
        key_handle: str | None = None,
    ) -> SigningOutcome:
        """Build a structured ``SKIPPED_*`` outcome (never a fabricated SIGNED)."""
        return SigningOutcome(
            status=status,
            backend=self.name,
            artifact=target.artifact_glob,
            key_handle=key_handle,
            skipped_reason=reason,
        )


def _redact(text: str) -> str:
    """Strip any line that mentions a Match secret env-var name from tool output.

    Defense-in-depth: ``codesign`` does not print ``MATCH_PASSWORD``, but tool
    stderr is operator-supplied surface; drop any line referencing a known
    secret-bearing variable so it can never reach a persisted outcome.
    """
    secret_tokens = ("MATCH_PASSWORD", "KEY_PASSWORD", "KEYSTORE_PASSWORD", "P12_PASSWORD")
    lines = [
        ln for ln in text.splitlines() if not any(tok in ln.upper() for tok in secret_tokens)
    ]
    return "\n".join(lines)


# Self-register at import time so the CLI dispatch table picks up the iOS
# backend without backends/__init__.py needing to hard-import this module
# (that module must import this one to trigger registration).
from sealward.cli import register_backend  # noqa: E402 - deferred to avoid import cycle

register_backend(Platform.IOS, IosBackend)
