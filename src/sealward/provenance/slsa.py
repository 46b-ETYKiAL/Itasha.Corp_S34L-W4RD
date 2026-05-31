"""SLSA provenance attestation (in-toto statement) for SealWard's own release.

This module emits a `SLSA v1.0 Provenance <https://slsa.dev/spec/v1.0/provenance>`_
predicate wrapped in an `in-toto Statement
<https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>`_ for
SealWard's OWN release artifacts. The statement binds each release artifact
(``subject``, by SHA-256 digest) to a build definition (the build process that
produced it) and the materials (inputs) that went into the build.

Stdlib-only (``hashlib`` + ``json`` + ``datetime``); no heavy dependency.

Honesty contract:

* **No fabricated digest.** Every ``subject`` digest is computed by streaming
  the named file from disk. A subject whose file does not exist is rejected
  with a ``FileNotFoundError`` rather than emitting a placeholder digest —
  the attestation never claims a hash it did not compute.
* **No secret in the attestation.** The statement carries only artifact paths,
  digests, the builder identity URI, the build type, and declared materials.
  There is no field that could carry credential material; the builder reads no
  environment secrets and no key handles.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path

__all__ = [
    "IN_TOTO_STATEMENT_TYPE",
    "SLSA_PREDICATE_TYPE",
    "BuildMaterial",
    "build_slsa_provenance",
    "render_slsa_json",
]

#: in-toto Statement v1 ``_type`` discriminator.
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: SLSA v1.0 Provenance predicate type.
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


class BuildMaterial:
    """A single declared build input (a source repo / dependency resolved root).

    Carries ONLY a non-secret URI and an optional digest mapping (e.g.
    ``{"sha1": "<commit>"}`` or ``{"sha256": "<hash>"}``). Never a credential.
    """

    __slots__ = ("digest", "uri")

    def __init__(self, uri: str, digest: Mapping[str, str] | None = None) -> None:
        self.uri = uri
        self.digest = dict(digest) if digest else {}

    def to_dict(self) -> dict[str, object]:
        """Render this material as a SLSA ``resolvedDependencies`` entry."""
        entry: dict[str, object] = {"uri": self.uri}
        if self.digest:
            entry["digest"] = dict(self.digest)
        return entry


def _sha256(path: Path) -> str:
    """Stream a SHA-256 hex digest of ``path`` (chunked; never loads whole file).

    Raises:
        FileNotFoundError: when ``path`` does not exist — the builder refuses to
            attest a subject whose content it cannot hash (no fabricated digest).
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _subjects(artifacts: Iterable[Path]) -> list[dict[str, object]]:
    """Build the in-toto ``subject`` list, hashing each artifact from disk."""
    subjects: list[dict[str, object]] = []
    for artifact in artifacts:
        path = Path(artifact)
        subjects.append(
            {
                "name": path.name,
                "digest": {"sha256": _sha256(path)},
            }
        )
    if not subjects:
        raise ValueError("SLSA provenance requires at least one subject artifact")
    return subjects


def build_slsa_provenance(
    artifacts: Iterable[Path],
    *,
    builder_id: str,
    build_type: str,
    materials: Iterable[BuildMaterial] | None = None,
    invocation_id: str | None = None,
    started_on: datetime | None = None,
    finished_on: datetime | None = None,
    external_parameters: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Build a SLSA v1.0 provenance in-toto statement for ``artifacts``.

    Args:
        artifacts: Release artifact paths to attest. Each is hashed from disk
            and added as a ``subject`` (no fabricated digests).
        builder_id: URI identifying the build platform / CI identity that
            produced the artifacts (e.g. the GitHub Actions workflow ref).
        build_type: URI identifying the build process type (e.g. a GitHub
            Actions workflow build-type URI).
        materials: Declared build inputs (source repo, resolved deps). Emitted
            as ``runDetails`` ``resolvedDependencies``.
        invocation_id: Optional opaque build invocation id (a run id; never a
            secret).
        started_on: Optional build start time (UTC). Defaults to now.
        finished_on: Optional build finish time (UTC). Defaults to ``started_on``.
        external_parameters: Optional non-secret external build parameters
            (e.g. ``{"ref": "refs/tags/v0.1.0"}``).

    Returns:
        A dict matching the in-toto Statement v1 envelope carrying a SLSA v1.0
        provenance predicate. No field carries secret material.
    """
    started = (started_on or datetime.now(UTC)).astimezone(UTC)
    finished = (finished_on or started).astimezone(UTC)
    resolved = [m.to_dict() for m in (materials or [])]
    predicate: dict[str, object] = {
        "buildDefinition": {
            "buildType": build_type,
            "externalParameters": dict(external_parameters or {}),
            "internalParameters": {},
            "resolvedDependencies": resolved,
        },
        "runDetails": {
            "builder": {"id": builder_id},
            "metadata": {
                "invocationId": invocation_id or "",
                "startedOn": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "finishedOn": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
            },
        },
    }
    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": _subjects(artifacts),
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": predicate,
    }


def render_slsa_json(
    artifacts: Iterable[Path],
    *,
    builder_id: str,
    build_type: str,
    materials: Iterable[BuildMaterial] | None = None,
    invocation_id: str | None = None,
    started_on: datetime | None = None,
    finished_on: datetime | None = None,
    external_parameters: Mapping[str, object] | None = None,
    indent: int = 2,
) -> str:
    """Return :func:`build_slsa_provenance` rendered as a JSON string."""
    statement = build_slsa_provenance(
        artifacts,
        builder_id=builder_id,
        build_type=build_type,
        materials=materials,
        invocation_id=invocation_id,
        started_on=started_on,
        finished_on=finished_on,
        external_parameters=external_parameters,
    )
    return json.dumps(statement, indent=indent, sort_keys=False)
