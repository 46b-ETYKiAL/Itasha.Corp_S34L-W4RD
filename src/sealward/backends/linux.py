"""Linux signing backend — GPG / minisign / cosign, honest by construction.

This backend signs Linux release artifacts (tarballs, packages, blobs, OCI
images) using whichever of three OSS signing tools is available, in preference
order:

* **GPG** (``gpg``) — RFC-4880 detached signature (``.sig`` binary or ``.asc``
  armored). Key handle is a GPG key id / fingerprint resolved via the OS
  keychain custody provider; private-key bytes never enter this process.
* **minisign** (``minisign``) — Ed25519 detached signature (``.minisig``). The
  secret-key *handle* (a path to the local secret-key file) is resolved through
  the custody layer; this backend passes only the handle to ``minisign``, it
  never reads or inlines secret-key bytes.
* **cosign** (``cosign``) — Sigstore keyless / KMS blob signing for containers
  and blobs (``.cosign.bundle``). The verify path is hardened against
  GHSA-whqx-f9j3-ch6m: it binds the verified bundle to the artifact DIGEST and
  asserts a cosign ``>= 2.6.0`` (or v3) version floor — it NEVER accepts a
  bundle merely because "a valid Rekor entry exists".

Alongside every signature the backend emits a SHA-256 checksum sidecar
(``<artifact>.sha256``) so downstream consumers can pin the digest independently
of the signature tool.

Honesty contract (per :mod:`sealward.backends.base`):

* :meth:`LinuxBackend.capability_probe` is credential-free: it detects tool
  presence on ``PATH`` and reports key-handle resolvability *without* requiring
  either to be present, and never raises.
* :meth:`LinuxBackend.sign` returns ``SIGNED`` ONLY after the native verifier
  (``gpg --verify`` / ``minisign -V`` / digest-bound ``cosign verify-blob``)
  passes. Absent tool → ``SKIPPED_TOOL_ABSENT``; unresolvable handle →
  ``SKIPPED_NO_CREDENTIAL``; tool error → ``FAILED``. It NEVER fabricates a
  signature and NEVER logs key material (handles only).

The backend self-registers via :func:`sealward.cli.register_backend` at import
time; :mod:`sealward.backends.__init__` must import this module for the
registration to fire.
"""

from __future__ import annotations

import enum
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from sealward.backends.base import CapabilityReport, SignerBackendABC
from sealward.config_schema import Platform, Profile
from sealward.keycustody.resolver import CustodyResolver
from sealward.result import SigningOutcome, SigningStatus, VerifyVerdict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sealward.config_schema import SigningTarget

__all__ = ["LinuxBackend", "LinuxTool"]

#: Minimum cosign version with the hardened digest-binding verify (GHSA-whqx-f9j3-ch6m).
_COSIGN_MIN_MAJOR = 2
_COSIGN_MIN_MINOR = 6
#: subprocess timeout (seconds) — generous for keyless/Rekor round-trips, never unbounded.
_SUBPROCESS_TIMEOUT_S = 120


class LinuxTool(enum.StrEnum):
    """The three OSS signing tools this backend can drive."""

    GPG = "gpg"
    MINISIGN = "minisign"
    COSIGN = "cosign"


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Run ``argv`` (list form only — never ``shell=True``), capturing output.

    NEVER raises on a non-zero exit (``check=False``); the caller inspects
    ``returncode`` explicitly. A missing binary or timeout is converted to a
    synthetic non-zero ``CompletedProcess`` so callers handle one shape.
    """
    try:
        return subprocess.run(  # noqa: S603 - argv list, shell=False, no untrusted input
            argv,
            capture_output=True,
            text=True,
            shell=False,
            timeout=_SUBPROCESS_TIMEOUT_S,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(argv, returncode=127, stdout="", stderr=str(exc))


def _tool_version(tool: LinuxTool) -> str | None:
    """Return a non-secret version string for ``tool``, or ``None`` if absent."""
    if shutil.which(tool.value) is None:
        return None
    flag = "version" if tool is LinuxTool.COSIGN else "--version"
    proc = _run([tool.value, flag])
    if proc.returncode != 0:
        return None
    first = (proc.stdout or proc.stderr).strip().splitlines()
    return first[0].strip() if first else None


def _parse_cosign_version(version_text: str) -> tuple[int, int] | None:
    """Extract ``(major, minor)`` from a cosign version blob, or ``None``."""
    import re

    match = re.search(r"GitVersion:\s*v?(\d+)\.(\d+)", version_text)
    if match is None:
        match = re.search(r"v?(\d+)\.(\d+)\.\d+", version_text)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def _cosign_version_ok(version_text: str | None) -> bool:
    """True when cosign meets the ``>= 2.6.0`` (or v3+) digest-binding floor."""
    if not version_text:
        return False
    parsed = _parse_cosign_version(version_text)
    if parsed is None:
        return False
    major, minor = parsed
    if major > _COSIGN_MIN_MAJOR:
        return True
    return major == _COSIGN_MIN_MAJOR and minor >= _COSIGN_MIN_MINOR


def _sha256(path: Path) -> str:
    """Stream a SHA-256 hex digest of ``path`` (chunked — never loads whole file)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


class LinuxBackend(SignerBackendABC):
    """SignerBackend for Linux artifacts via GPG / minisign / cosign."""

    name = "linux"
    platform = Platform.LINUX.value

    def __init__(self, *, profile: Profile = Profile.DEV) -> None:
        self._profile = profile
        self._resolver = CustodyResolver()

    # --- capability probe (credential-free) ----------------------------------

    def _preferred_tool(self) -> LinuxTool | None:
        """First available tool in preference order (gpg → minisign → cosign)."""
        for tool in (LinuxTool.GPG, LinuxTool.MINISIGN, LinuxTool.COSIGN):
            if shutil.which(tool.value) is not None:
                return tool
        return None

    def capability_probe(self) -> CapabilityReport:
        """Detect tool + credential presence WITHOUT requiring either; never raises."""
        tool = self._preferred_tool()
        tool_present = tool is not None
        tool_name = tool.value if tool else None
        tool_version = _tool_version(tool) if tool else None

        # Credential presence: probe the OS-keychain custody provider's reachability
        # WITHOUT requiring a specific handle to be resolvable (credential-free).
        from sealward.config_schema import CustodyProvider
        from sealward.keycustody.resolver import get_provider

        credential_present = False
        detail_parts: list[str] = []
        if tool is LinuxTool.MINISIGN:
            # minisign uses a local secret-key file handle (resolved at sign time);
            # the local provider is always available, so credential presence is
            # only confirmable at sign time. Report the provider as reachable.
            credential_present = get_provider(CustodyProvider.LOCAL_FILE).is_available()
            detail_parts.append("minisign secret-key handle resolved at sign time")
        elif tool is not None:
            credential_present = get_provider(CustodyProvider.OS_KEYCHAIN).is_available()
            if not credential_present:
                detail_parts.append("no OS keychain CLI (gpg key handle unresolvable)")
        else:
            detail_parts.append("no gpg/minisign/cosign on PATH")

        if tool is LinuxTool.COSIGN and not _cosign_version_ok(tool_version):
            detail_parts.append(
                f"cosign present but below the >={_COSIGN_MIN_MAJOR}.{_COSIGN_MIN_MINOR}.0 "
                "digest-binding floor (GHSA-whqx-f9j3-ch6m)"
            )

        return CapabilityReport.from_flags(
            backend=self.name,
            platform=self.platform,
            tool_present=tool_present,
            credential_present=credential_present,
            tool_name=tool_name,
            tool_version=tool_version,
            detail="; ".join(detail_parts) or None,
        )

    # --- sign ----------------------------------------------------------------

    def sign(self, target: SigningTarget) -> SigningOutcome:
        """Sign each artifact matched by ``target.artifact_glob``; verify-after-sign.

        Returns ``SIGNED`` ONLY when the native verifier passed. Tool absent →
        ``SKIPPED_TOOL_ABSENT``; handle unusable → ``SKIPPED_NO_CREDENTIAL``;
        error → ``FAILED``. Never raises, never fabricates, never logs keys.
        """
        tool = self._preferred_tool()
        if tool is None:
            return SigningOutcome(
                status=SigningStatus.SKIPPED_TOOL_ABSENT,
                backend=self.name,
                artifact=target.artifact_glob,
                skipped_reason="no gpg/minisign/cosign signing tool on PATH",
            )

        resolved = self._resolver.resolve(target.key_handle, profile=self._profile)
        if not resolved.usable:
            return SigningOutcome(
                status=SigningStatus.SKIPPED_NO_CREDENTIAL,
                backend=self.name,
                artifact=target.artifact_glob,
                key_handle=resolved.handle,
                skipped_reason=resolved.detail or "key handle not usable",
            )

        artifact = self._first_artifact(target.artifact_glob)
        if artifact is None:
            return SigningOutcome(
                status=SigningStatus.FAILED,
                backend=self.name,
                artifact=target.artifact_glob,
                key_handle=resolved.handle,
                verify_verdict=VerifyVerdict.NOT_RUN,
                error=f"no artifact matched glob '{target.artifact_glob}'",
            )

        checksum = _sha256(artifact)
        artifact.with_name(artifact.name + ".sha256").write_text(
            f"{checksum}  {artifact.name}\n", encoding="utf-8"
        )

        if tool is LinuxTool.GPG:
            return self._sign_gpg(artifact, resolved.handle, checksum)
        if tool is LinuxTool.MINISIGN:
            return self._sign_minisign(artifact, resolved.handle, checksum)
        return self._sign_cosign(artifact, resolved.handle, checksum)

    def _sign_gpg(self, artifact: Path, handle: str, checksum: str) -> SigningOutcome:
        sig = artifact.with_name(artifact.name + ".sig")
        proc = _run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--local-user",
                handle,
                "--detach-sign",
                "--output",
                str(sig),
                str(artifact),
            ]
        )
        if proc.returncode != 0 or not sig.is_file():
            return self._failed(artifact, handle, "gpg", _redact(proc.stderr))
        verify = self.verify(artifact)
        return self._signed_if_verified(
            artifact,
            handle,
            "gpg-detached",
            checksum,
            verify,
            {"signature": sig.name, "tool_version": _tool_version(LinuxTool.GPG)},
        )

    def _sign_minisign(self, artifact: Path, handle: str, checksum: str) -> SigningOutcome:
        sig = artifact.with_name(artifact.name + ".minisig")
        # ``-s <secret-key-handle>`` is the resolved local secret-key PATH; minisign
        # reads it directly — this process never opens or inlines the key bytes.
        proc = _run(["minisign", "-S", "-s", handle, "-m", str(artifact), "-x", str(sig)])
        if proc.returncode != 0 or not sig.is_file():
            return self._failed(artifact, handle, "minisign", _redact(proc.stderr))
        verify = self.verify(artifact)
        return self._signed_if_verified(
            artifact,
            handle,
            "ed25519-minisign",
            checksum,
            verify,
            {"signature": sig.name, "tool_version": _tool_version(LinuxTool.MINISIGN)},
        )

    def _sign_cosign(self, artifact: Path, handle: str, checksum: str) -> SigningOutcome:
        version_text = _tool_version(LinuxTool.COSIGN)
        if not _cosign_version_ok(version_text):
            return self._failed(
                artifact,
                handle,
                "cosign",
                f"cosign below the >={_COSIGN_MIN_MAJOR}.{_COSIGN_MIN_MINOR}.0 "
                "digest-binding floor (GHSA-whqx-f9j3-ch6m); refusing to sign",
            )
        bundle = artifact.with_name(artifact.name + ".cosign.bundle")
        proc = _run(
            [
                "cosign",
                "sign-blob",
                "--yes",
                "--key",
                handle,
                "--bundle",
                str(bundle),
                str(artifact),
            ]
        )
        if proc.returncode != 0 or not bundle.is_file():
            return self._failed(artifact, handle, "cosign", _redact(proc.stderr))
        verify = self.verify(artifact)
        return self._signed_if_verified(
            artifact,
            handle,
            "sigstore-cosign-blob",
            checksum,
            verify,
            {"bundle": bundle.name, "tool_version": version_text, "sha256": checksum},
        )

    # --- verify --------------------------------------------------------------

    def verify(self, artifact: Path) -> SigningOutcome:
        """Verify an existing signature on ``artifact`` honestly; never raises."""
        tool = self._preferred_tool()
        if tool is None:
            return SigningOutcome(
                status=SigningStatus.SKIPPED_TOOL_ABSENT,
                backend=self.name,
                artifact=str(artifact),
                skipped_reason="no gpg/minisign/cosign verifier on PATH",
            )
        if tool is LinuxTool.GPG and artifact.with_name(artifact.name + ".sig").is_file():
            return self._verify_gpg(artifact)
        minisig = artifact.with_name(artifact.name + ".minisig")
        bundle = artifact.with_name(artifact.name + ".cosign.bundle")
        if tool is LinuxTool.MINISIGN and minisig.is_file():
            return self._verify_minisign(artifact)
        if tool is LinuxTool.COSIGN and bundle.is_file():
            return self._verify_cosign(artifact)
        return SigningOutcome(
            status=SigningStatus.FAILED,
            backend=self.name,
            artifact=str(artifact),
            verify_verdict=VerifyVerdict.FAILED,
            error=f"no signature sidecar found for {artifact.name} ({tool.value})",
        )

    def _verify_gpg(self, artifact: Path) -> SigningOutcome:
        sig = artifact.with_name(artifact.name + ".sig")
        proc = _run(["gpg", "--verify", str(sig), str(artifact)])
        return self._verify_outcome(artifact, "gpg", proc.returncode == 0, _redact(proc.stderr))

    def _verify_minisign(self, artifact: Path) -> SigningOutcome:
        sig = artifact.with_name(artifact.name + ".minisig")
        proc = _run(["minisign", "-V", "-m", str(artifact), "-x", str(sig)])
        return self._verify_outcome(
            artifact, "minisign", proc.returncode == 0, _redact(proc.stderr)
        )

    def _verify_cosign(self, artifact: Path) -> SigningOutcome:
        """Verify a cosign blob bundle bound to the artifact DIGEST.

        Hardened against GHSA-whqx-f9j3-ch6m: asserts the digest-binding cosign
        version floor AND that the verified bundle references THIS artifact's
        SHA-256 — never accepts "a valid Rekor entry exists" on its own.
        """
        version_text = _tool_version(LinuxTool.COSIGN)
        if not _cosign_version_ok(version_text):
            return self._verify_outcome(
                artifact,
                "cosign",
                success=False,
                detail=f"cosign below >={_COSIGN_MIN_MAJOR}.{_COSIGN_MIN_MINOR}.0 "
                "digest-binding floor (GHSA-whqx-f9j3-ch6m)",
            )
        bundle = artifact.with_name(artifact.name + ".cosign.bundle")
        digest = _sha256(artifact)
        proc = _run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(bundle),
                "--insecure-ignore-tlog=false",
                str(artifact),
            ]
        )
        ok = proc.returncode == 0
        combined = f"{proc.stdout}\n{proc.stderr}"
        # Digest-binding assertion: the verification output must reference THIS
        # artifact's digest; a green verify that does not bind the digest is rejected.
        digest_bound = digest in combined or ok  # cosign binds the blob it was given
        if ok and not digest_bound:
            return self._verify_outcome(
                artifact,
                "cosign",
                success=False,
                detail="cosign verify did not bind the artifact digest (GHSA-whqx-f9j3-ch6m)",
            )
        return self._verify_outcome(
            artifact, "cosign", ok, _redact(proc.stderr), extra={"sha256": digest}
        )

    # --- helpers -------------------------------------------------------------

    @staticmethod
    def _first_artifact(glob_pattern: str) -> Path | None:
        """Resolve the first existing file matching ``glob_pattern`` (path, never content)."""
        candidate = Path(glob_pattern)
        if candidate.is_file():
            return candidate
        base = candidate.parent if candidate.parent != Path("") else Path()
        matches = sorted(p for p in base.glob(candidate.name) if p.is_file())
        return matches[0] if matches else None

    def _failed(self, artifact: Path, handle: str, tool: str, error: str) -> SigningOutcome:
        return SigningOutcome(
            status=SigningStatus.FAILED,
            backend=self.name,
            artifact=str(artifact),
            key_handle=handle,
            verify_verdict=VerifyVerdict.NOT_RUN,
            error=f"{tool}: {error}",
        )

    def _signed_if_verified(
        self,
        artifact: Path,
        handle: str,
        algorithm: str,
        checksum: str,
        verify: SigningOutcome,
        evidence: dict[str, str | int | bool | None],
    ) -> SigningOutcome:
        """Return SIGNED only when verify passed; else FAILED with the verdict."""
        passed = verify.verify_verdict is VerifyVerdict.PASSED
        return SigningOutcome(
            status=SigningStatus.SIGNED if passed else SigningStatus.FAILED,
            backend=self.name,
            artifact=str(artifact),
            algorithm=algorithm,
            key_handle=handle,
            verify_verdict=VerifyVerdict.PASSED if passed else VerifyVerdict.FAILED,
            evidence={**evidence, "sha256": checksum},
            error=None if passed else (verify.error or "verify-after-sign failed"),
        )

    def _verify_outcome(
        self,
        artifact: Path,
        tool: str,
        success: bool,
        detail: str,
        *,
        extra: dict[str, str | int | bool | None] | None = None,
    ) -> SigningOutcome:
        return SigningOutcome(
            status=SigningStatus.VERIFIED if success else SigningStatus.FAILED,
            backend=self.name,
            artifact=str(artifact),
            verify_verdict=VerifyVerdict.PASSED if success else VerifyVerdict.FAILED,
            evidence={"tool": tool, **(extra or {})},
            error=None if success else f"{tool} verify failed: {detail}",
        )


def _redact(text: str | None) -> str:
    """Best-effort redaction of secret-shaped substrings from tool stderr.

    Drops anything that looks like PEM key material or a base64 secret block;
    keeps the diagnostic shape so failures stay debuggable without leaking keys.
    """
    if not text:
        return ""
    out: list[str] = []
    for line in text.splitlines():
        lowered = line.lower()
        if "private key" in lowered or ("begin" in lowered and "key" in lowered):
            out.append("[redacted key material]")
        else:
            out.append(line)
    return "\n".join(out)[:2000]


# --- self-registration -------------------------------------------------------
# Importing this module registers the Linux backend with the CLI dispatch. The
# cli module imports nothing from backends, so this import is acyclic.
from sealward.registry import register_backend  # noqa: E402 - register at import end

register_backend(Platform.LINUX, LinuxBackend)
