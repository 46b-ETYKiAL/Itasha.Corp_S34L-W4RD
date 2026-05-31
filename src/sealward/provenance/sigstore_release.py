"""Sigstore keyless own-release provenance (Fulcio ephemeral cert + Rekor log).

This module signs SealWard's OWN release artifacts using Sigstore keyless
signing — the dogfood path that lets consumers verify the SealWard binary they
pin was published by SealWard's CI OIDC identity through an auditable
transparency log. No long-lived private key is ever used: Fulcio issues a
short-lived certificate bound to an OIDC identity, and the signing event is
recorded in the Rekor transparency log.

It ports the keyless-cosign shape from :mod:`sealward.backends.linux` to the
Python `sigstore <https://pypi.org/project/sigstore/>`_ library and reuses the
:class:`~sealward.result.SigningOutcome` honesty model.

Security floors (enforced, never advisory):

* **sigstore-python >= 4.0.1** (``_SIGSTORE_MIN_VERSION``) — mitigates
  CVE-2026-24137. A lower installed version degrades to a structured
  ``skipped`` outcome with ``skipped_reason`` naming the floor; it NEVER signs
  with a vulnerable library.
* **Digest-bound bundle** (GHSA-whqx-f9j3-ch6m) — the verify path asserts the
  Sigstore bundle binds the artifact's SHA-256 digest. A bundle whose Rekor
  entry is not bound to the artifact digest is REJECTED, never accepted on the
  bare existence of a valid transparency-log entry.

Optional-dependency guard:

``sigstore`` is an OPTIONAL dependency (``pip install sealward[sigstore]``). The
import is guarded; when the library is absent the module stays importable and
every operation returns a structured ``SKIPPED_TOOL_ABSENT`` outcome with
``skipped_reason="sigstore-unavailable: ..."``. The module NEVER fabricates a
``SIGNED`` result and NEVER logs key material (there is none — keyless).
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sealward.result import SigningOutcome, SigningStatus, VerifyVerdict

if TYPE_CHECKING:  # pragma: no cover - typing only
    pass

try:  # silence-reason: optional-import
    import sigstore as _sigstore  # type: ignore[import-not-found]

    _SIGSTORE_AVAILABLE = True
except ImportError:  # silence-reason: optional-import
    _sigstore = None  # type: ignore[assignment]
    _SIGSTORE_AVAILABLE = False

__all__ = [
    "SIGSTORE_MIN_VERSION",
    "SigstoreReleaseSigner",
    "sigstore_available",
    "sigstore_version",
]

#: Minimum sigstore-python version with the CVE-2026-24137 fix.
SIGSTORE_MIN_VERSION = (4, 0, 1)

#: Backend identifier carried on every outcome this module produces.
_BACKEND = "sigstore-release"

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def sigstore_available() -> bool:
    """Return ``True`` when the optional ``sigstore`` library is importable."""
    return _SIGSTORE_AVAILABLE


def sigstore_version() -> str | None:
    """Return the installed sigstore-python version string, or ``None``."""
    if not _SIGSTORE_AVAILABLE:
        return None
    version = getattr(_sigstore, "__version__", None)
    if isinstance(version, str) and version:
        return version
    try:
        import importlib.metadata as importlib_metadata

        return importlib_metadata.version("sigstore")
    except Exception:  # silence-reason: caller-contract
        return None


def _parse_version(version_text: str | None) -> tuple[int, int, int] | None:
    """Extract ``(major, minor, patch)`` from a version string, or ``None``."""
    if not version_text:
        return None
    match = _VERSION_RE.search(version_text)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _version_ok(version_text: str | None) -> bool:
    """True when the installed sigstore meets the CVE-2026-24137 floor."""
    parsed = _parse_version(version_text)
    return parsed is not None and parsed >= SIGSTORE_MIN_VERSION


def _sha256(path: Path) -> str:
    """Stream a SHA-256 hex digest of ``path`` (chunked; never loads whole file)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


class SigstoreReleaseSigner:
    """Keyless Sigstore signer/verifier for SealWard's own release artifacts.

    The signing client is INJECTABLE (``client`` constructor arg) so unit tests
    can pass a fake/mock and assert graceful degradation without contacting the
    real Fulcio/Rekor services. When no client is injected and the ``sigstore``
    library is present, a real client is constructed lazily at sign time.
    """

    name = _BACKEND

    def __init__(self, *, client: Any | None = None) -> None:
        """Create a signer.

        Args:
            client: Optional pre-built signing client (a real
                ``sigstore.sign.Signer`` or a test fake). When ``None``, a real
                client is built lazily — but only if the ``sigstore`` library is
                present and meets the version floor.
        """
        self._client = client

    # --- preconditions -------------------------------------------------------

    def _unavailable_outcome(self, artifact: str | None, reason: str) -> SigningOutcome:
        """Build the structured 'cannot proceed' outcome (never SIGNED)."""
        return SigningOutcome(
            status=SigningStatus.SKIPPED_TOOL_ABSENT,
            backend=self.name,
            artifact=artifact,
            algorithm="sigstore-keyless",
            skipped_reason=reason,
        )

    def _precondition_skip(self, artifact: str | None) -> SigningOutcome | None:
        """Return a SKIPPED outcome when sigstore is absent or below the floor.

        A test-injected client bypasses the library-presence check (the fake
        provides the surface) but the version floor is still asserted whenever
        a real library is importable, so a vulnerable real install can never
        sign even if a client was passed.
        """
        if not _SIGSTORE_AVAILABLE and self._client is None:
            return self._unavailable_outcome(
                artifact,
                "sigstore-unavailable: install the optional 'sigstore' extra "
                "(pip install sealward[sigstore])",
            )
        if _SIGSTORE_AVAILABLE:
            version = sigstore_version()
            if not _version_ok(version):
                floor = ".".join(str(n) for n in SIGSTORE_MIN_VERSION)
                return self._unavailable_outcome(
                    artifact,
                    f"sigstore-unavailable: installed version {version!r} is below "
                    f"the >={floor} floor (CVE-2026-24137); refusing to sign",
                )
        return None

    # --- sign ----------------------------------------------------------------

    def sign(self, artifact: Path) -> SigningOutcome:
        """Keyless-sign ``artifact``; verify-after-sign; never raise/fabricate.

        Returns ``SIGNED`` ONLY when a bundle was produced AND the verify path
        confirmed the bundle binds this artifact's digest. Library absent or
        below the floor → ``SKIPPED_TOOL_ABSENT``; signing error → ``FAILED``.
        """
        skip = self._precondition_skip(str(artifact))
        if skip is not None:
            return skip
        if not artifact.is_file():
            return SigningOutcome(
                status=SigningStatus.FAILED,
                backend=self.name,
                artifact=str(artifact),
                algorithm="sigstore-keyless",
                verify_verdict=VerifyVerdict.NOT_RUN,
                error=f"artifact not found: {artifact}",
            )

        digest = _sha256(artifact)
        bundle_path = artifact.with_name(artifact.name + ".sigstore.json")
        try:
            client = self._client or self._build_client()
            result = client.sign_artifact(artifact)  # fake or real client surface
            bundle = getattr(result, "bundle", result)
            log_index = getattr(result, "log_index", None)
            self._write_bundle(bundle_path, bundle)
        except Exception as exc:  # silence-reason: caller-contract
            return SigningOutcome(
                status=SigningStatus.FAILED,
                backend=self.name,
                artifact=str(artifact),
                algorithm="sigstore-keyless",
                verify_verdict=VerifyVerdict.NOT_RUN,
                error=_redact(str(exc)),
            )

        verify = self.verify(artifact)
        passed = verify.verify_verdict is VerifyVerdict.PASSED
        evidence: dict[str, str | int | bool | None] = {
            "bundle": bundle_path.name,
            "sha256": digest,
            "transparency_log": "rekor",
            "sigstore_version": sigstore_version(),
        }
        if log_index is not None:
            evidence["rekor_log_index"] = int(log_index)
        return SigningOutcome(
            status=SigningStatus.SIGNED if passed else SigningStatus.FAILED,
            backend=self.name,
            artifact=str(artifact),
            algorithm="sigstore-keyless",
            verify_verdict=VerifyVerdict.PASSED if passed else VerifyVerdict.FAILED,
            evidence=evidence,
            error=None if passed else (verify.error or "verify-after-sign failed"),
        )

    # --- verify --------------------------------------------------------------

    def verify(self, artifact: Path) -> SigningOutcome:
        """Verify the Sigstore bundle for ``artifact``, BOUND to its digest.

        Hardened against GHSA-whqx-f9j3-ch6m: a bundle is accepted ONLY when the
        client confirms it AND the bundle binds this artifact's SHA-256. A green
        verify that does not bind the digest is rejected.
        """
        skip = self._precondition_skip(str(artifact))
        if skip is not None:
            return skip
        bundle_path = artifact.with_name(artifact.name + ".sigstore.json")
        if not bundle_path.is_file():
            return SigningOutcome(
                status=SigningStatus.FAILED,
                backend=self.name,
                artifact=str(artifact),
                verify_verdict=VerifyVerdict.FAILED,
                error=f"no sigstore bundle found for {artifact.name}",
            )
        digest = _sha256(artifact)
        try:
            client = self._client or self._build_client()
            bundle_bytes = bundle_path.read_bytes()
            verdict = client.verify_artifact(artifact, bundle_bytes)
            ok = bool(getattr(verdict, "verified", verdict))
            bound_digest = getattr(verdict, "artifact_digest", None)
        except Exception as exc:  # silence-reason: caller-contract
            return SigningOutcome(
                status=SigningStatus.FAILED,
                backend=self.name,
                artifact=str(artifact),
                verify_verdict=VerifyVerdict.FAILED,
                error=_redact(str(exc)),
            )
        # Digest-binding assertion (GHSA-whqx-f9j3-ch6m): when the verdict
        # reports the bound digest it MUST equal this artifact's digest. A
        # verdict that omits the digest cannot prove binding → reject.
        digest_bound = bound_digest is not None and str(bound_digest) == digest
        if ok and not digest_bound:
            return SigningOutcome(
                status=SigningStatus.FAILED,
                backend=self.name,
                artifact=str(artifact),
                verify_verdict=VerifyVerdict.FAILED,
                evidence={"sha256": digest},
                error="sigstore bundle not bound to artifact digest (GHSA-whqx-f9j3-ch6m)",
            )
        return SigningOutcome(
            status=SigningStatus.VERIFIED if ok else SigningStatus.FAILED,
            backend=self.name,
            artifact=str(artifact),
            verify_verdict=VerifyVerdict.PASSED if ok else VerifyVerdict.FAILED,
            evidence={"sha256": digest, "digest_bound": bool(digest_bound)},
            error=None if ok else "sigstore verification failed",
        )

    # --- helpers -------------------------------------------------------------

    def _build_client(self) -> Any:
        """Lazily build a real Sigstore signing client (production path).

        Only reachable when the ``sigstore`` library is present and at/above the
        version floor (both checked by :meth:`_precondition_skip` first). Kept
        thin so the production wiring is obvious; tests inject ``client`` and
        never reach here.
        """
        # The real client construction surface varies across sigstore-python
        # 4.x; the release workflow injects a concrete pre-built client. This
        # lazy path constructs the documented keyless client when available.
        from sigstore.sign import SigningContext  # type: ignore[import-not-found]

        return SigningContext.production()

    @staticmethod
    def _write_bundle(path: Path, bundle: Any) -> None:
        """Write the Sigstore bundle to disk (bytes or str), never key material."""
        if isinstance(bundle, (bytes, bytearray)):
            path.write_bytes(bytes(bundle))
        elif isinstance(bundle, str):
            path.write_text(bundle, encoding="utf-8")
        else:
            # Bundle objects expose ``to_json``; fall back to ``str`` honestly.
            to_json = getattr(bundle, "to_json", None)
            payload = to_json() if callable(to_json) else str(bundle)
            path.write_text(payload, encoding="utf-8")


def _redact(text: str | None) -> str:
    """Best-effort redaction of key-shaped substrings from error text."""
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


#: Default artifact globs the release signer targets inside the dist dir.
_DEFAULT_ARTIFACT_GLOBS = ("*.whl", "*.tar.gz")

#: The bundle suffix this signer writes; the workflow's --bundle-suffix MUST match.
_BUNDLE_SUFFIX = ".sigstore.json"


def main(argv: list[str] | None = None) -> int:
    """Module CLI: keyless-sign every release artifact in a dist directory.

    Invoked by the release workflow as ``python -m
    sealward.provenance.sigstore_release --dist dist --bundle-suffix
    .sigstore.json``. Signs each ``*.whl`` / ``*.tar.gz`` under ``--dist`` via
    :class:`SigstoreReleaseSigner`, writing a ``<artifact>.sigstore.json``
    bundle next to each.

    Exit codes (never raises into the process):

    * ``0`` — every artifact signed + verify-after-sign passed.
    * ``2`` — at least one artifact FAILED to sign, OR ``--dist`` is missing /
      contains no signable artifact.
    * ``3`` — the optional ``sigstore`` library is absent / below the
      CVE-2026-24137 floor (every artifact SKIPPED). This is an honest "could
      not sign" signal — the workflow installs ``sigstore==4.0.1`` so this code
      indicates a misconfigured environment, never a fabricated success.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m sealward.provenance.sigstore_release",
        description="Sigstore keyless-sign SealWard's own release artifacts.",
    )
    parser.add_argument(
        "--dist",
        type=Path,
        required=True,
        help="directory containing the release artifacts to sign",
    )
    parser.add_argument(
        "--bundle-suffix",
        default=_BUNDLE_SUFFIX,
        help=f"bundle filename suffix (must be {_BUNDLE_SUFFIX!r}; the only suffix written)",
    )
    args = parser.parse_args(argv)

    if args.bundle_suffix != _BUNDLE_SUFFIX:
        print(
            f"error: --bundle-suffix must be {_BUNDLE_SUFFIX!r} "
            f"(the signer writes only that suffix); got {args.bundle_suffix!r}",
            file=sys.stderr,
        )
        return 2

    dist: Path = args.dist
    if not dist.is_dir():
        print(f"error: --dist directory not found: {dist}", file=sys.stderr)
        return 2

    artifacts: list[Path] = []
    for pattern in _DEFAULT_ARTIFACT_GLOBS:
        artifacts.extend(sorted(dist.glob(pattern)))
    if not artifacts:
        print(f"error: no *.whl / *.tar.gz artifacts found under {dist}", file=sys.stderr)
        return 2

    signer = SigstoreReleaseSigner()
    failed: list[str] = []
    skipped: list[str] = []
    signed: list[str] = []
    for artifact in artifacts:
        outcome = signer.sign(artifact)
        if outcome.status is SigningStatus.SIGNED:
            signed.append(artifact.name)
            print(f"signed: {artifact.name} -> {artifact.name}{_BUNDLE_SUFFIX}", file=sys.stderr)
        elif outcome.status is SigningStatus.SKIPPED_TOOL_ABSENT:
            skipped.append(artifact.name)
            print(f"skipped: {artifact.name} ({outcome.skipped_reason})", file=sys.stderr)
        else:
            failed.append(artifact.name)
            print(f"FAILED: {artifact.name} ({outcome.error})", file=sys.stderr)

    if failed:
        return 2
    if skipped and not signed:
        # Every artifact was skipped (sigstore unavailable / below floor) — honest
        # "could not sign" rather than a green that signed nothing.
        return 3
    print(f"sigstore: signed {len(signed)} artifact(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover - module CLI entry point
    raise SystemExit(main())
