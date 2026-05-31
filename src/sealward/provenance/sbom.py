"""CycloneDX 1.6 SBOM generation for SealWard's OWN dependency tree.

This module emits a valid `CycloneDX 1.6 <https://cyclonedx.org/docs/1.6/json/>`_
Software Bill of Materials for the SealWard package itself, built from the
installed/declared dependency tree using ONLY the Python standard library — no
heavy third-party SBOM generator is required (and none is a runtime dep).

Design contract:

* **No dep omitted.** The builder enumerates every pinned dependency declared in
  the SealWard distribution metadata (the ``Requires-Dist`` entries of the
  installed ``sealward`` distribution, including the optional-dependency extras)
  and, when reachable, the installed version of each. The root ``sealward``
  component is emitted as the SBOM's ``metadata.component``.
* **No secret in the SBOM.** Only package NAME + VERSION + a deterministic PURL
  go into the document. There is no field that could carry credential material;
  the builder never reads source, environment, or key handles.
* **Honest by construction.** When a declared dependency's installed version is
  not resolvable (the package is declared but not installed in the current
  environment), the component is still emitted with the *declared* version
  constraint and a ``properties`` note marking it ``declared-not-installed`` —
  the builder never fabricates a concrete version it did not observe.

The output is a Python ``dict`` (and a JSON string via :func:`render_sbom_json`)
that the release workflow / CLI can write next to the release artifacts.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import re
import tomllib
import uuid
from datetime import UTC, datetime
from pathlib import Path

__all__ = [
    "CYCLONEDX_SPEC_VERSION",
    "DEFAULT_DISTRIBUTION",
    "SbomComponent",
    "build_sbom",
    "render_sbom_json",
]

#: The CycloneDX JSON spec version this builder targets.
CYCLONEDX_SPEC_VERSION = "1.6"

#: The CycloneDX JSON ``bomFormat`` discriminator (fixed by the spec).
_BOM_FORMAT = "CycloneDX"

#: The distribution whose dependency tree this SBOM describes.
DEFAULT_DISTRIBUTION = "sealward"

#: Matches the leading PEP 508 package name in a ``Requires-Dist`` string.
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

#: Extracts the pinned/declared version constraint from a ``Requires-Dist`` string.
_VERSION_RE = re.compile(r"(==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9][A-Za-z0-9.+!*-]*)")


class SbomComponent:
    """A single CycloneDX ``component`` (a package name + version + PURL).

    Carries ONLY non-secret metadata. ``installed`` records whether the concrete
    version was observed in the environment (``True``) or is the declared
    constraint only (``False``) — the honesty flag that prevents fabricating a
    version that was never installed.
    """

    __slots__ = ("installed", "name", "version")

    def __init__(self, name: str, version: str, *, installed: bool) -> None:
        self.name = name
        self.version = version
        self.installed = installed

    def purl(self) -> str:
        """Return the deterministic Package URL for this component."""
        return f"pkg:pypi/{self.name.lower()}@{self.version}"

    def to_dict(self) -> dict[str, object]:
        """Render this component as a CycloneDX 1.6 ``component`` object."""
        component: dict[str, object] = {
            "type": "library",
            "name": self.name,
            "version": self.version,
            "purl": self.purl(),
            "bom-ref": self.purl(),
        }
        if not self.installed:
            component["properties"] = [
                {
                    "name": "sealward:resolution",
                    "value": "declared-not-installed",
                }
            ]
        return component


def _parse_requirement(requires_dist: str) -> tuple[str, str, bool] | None:
    """Parse a ``Requires-Dist`` entry into ``(name, version, is_pinned)``.

    Returns ``None`` for an unparseable entry. ``is_pinned`` is ``True`` when an
    exact ``==`` pin was found; the declared version string is returned either
    way (constraint text when no exact pin).
    """
    name_match = _NAME_RE.match(requires_dist)
    if name_match is None:
        return None
    name = name_match.group(1)
    pinned = False
    version = "unknown"
    ver_match = _VERSION_RE.search(requires_dist)
    if ver_match is not None:
        operator, value = ver_match.group(1), ver_match.group(2)
        version = value
        pinned = operator == "=="
    return name, version, pinned


def _installed_version(name: str) -> str | None:
    """Return the installed version of ``name``, or ``None`` if not installed."""
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return None
    except Exception:  # silence-reason: caller-contract
        # Metadata access must never raise into the SBOM builder; an
        # unresolvable name degrades to "declared only", never a crash.
        return None


def _find_pyproject() -> Path | None:
    """Locate the project ``pyproject.toml`` by walking up from this module.

    Used as the dependency source-of-truth when ``distribution`` is NOT
    installed as a wheel/dist (the canonical PYTHONPATH dev workflow). Returns
    ``None`` when no ``pyproject.toml`` is found above this file.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "pyproject.toml"
        if candidate.is_file():
            return candidate
    return None


def _requirements_from_pyproject() -> list[str]:
    """Read declared deps (core + every optional extra) from ``pyproject.toml``.

    Returns a flat list of PEP 508 requirement strings. The fallback used when
    distribution metadata is absent; honest by construction (it reads only the
    declared manifest, never fabricates a dep).
    """
    pyproject = _find_pyproject()
    if pyproject is None:
        return []
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):  # silence-reason: caller-contract
        return []
    project = data.get("project", {})
    requirements: list[str] = list(project.get("dependencies", []) or [])
    optional = project.get("optional-dependencies", {}) or {}
    for group in optional.values():
        requirements.extend(group or [])
    return requirements


def _collect_components(distribution: str) -> list[SbomComponent]:
    """Enumerate every declared dependency of ``distribution`` as a component.

    Reads ``Requires-Dist`` from the installed distribution metadata (covers core
    deps AND every optional-dependency extra, since extras are encoded as
    ``Requires-Dist`` entries with an environment marker). When the distribution
    is NOT installed (the canonical PYTHONPATH dev workflow), falls back to the
    declared deps in ``pyproject.toml``. Each declared dep becomes one component;
    the concrete installed version is preferred over the declared constraint,
    with the honesty flag set accordingly.
    """
    try:
        dist = importlib_metadata.distribution(distribution)
        requires = dist.requires or []
    except importlib_metadata.PackageNotFoundError:
        requires = _requirements_from_pyproject()
    seen: dict[str, SbomComponent] = {}
    for entry in requires:
        parsed = _parse_requirement(entry)
        if parsed is None:
            continue
        name, declared_version, _pinned = parsed
        key = name.lower()
        installed = _installed_version(name)
        version = installed if installed is not None else declared_version
        component = SbomComponent(name, version, installed=installed is not None)
        # Prefer an installed observation over a prior declared-only sighting of
        # the same package (extras can list the same dep under multiple markers).
        existing = seen.get(key)
        if existing is None or (component.installed and not existing.installed):
            seen[key] = component
    return sorted(seen.values(), key=lambda c: c.name.lower())


def _root_component(distribution: str) -> dict[str, object]:
    """Build the SBOM ``metadata.component`` for the SealWard root package."""
    version = _installed_version(distribution) or "0.0.0"
    purl = f"pkg:pypi/{distribution.lower()}@{version}"
    return {
        "type": "application",
        "name": distribution,
        "version": version,
        "purl": purl,
        "bom-ref": purl,
    }


def build_sbom(
    distribution: str = DEFAULT_DISTRIBUTION,
    *,
    serial_number: str | None = None,
    timestamp: datetime | None = None,
) -> dict[str, object]:
    """Build a valid CycloneDX 1.6 SBOM ``dict`` for ``distribution``.

    Args:
        distribution: The installed distribution to describe (default
            ``"sealward"``).
        serial_number: Optional fixed ``serialNumber`` (a ``urn:uuid:...``).
            When omitted a random UUID-4 urn is generated; pass a fixed value
            for deterministic/reproducible output.
        timestamp: Optional fixed ``metadata.timestamp``. Defaults to the
            current UTC time.

    Returns:
        A dict matching the CycloneDX 1.6 JSON schema with ``bomFormat``,
        ``specVersion``, ``serialNumber``, ``version``, ``metadata`` (with the
        root component), and ``components`` (one per declared dependency). No
        field carries secret material.
    """
    when = (timestamp or datetime.now(UTC)).astimezone(UTC)
    serial = serial_number or f"urn:uuid:{uuid.uuid4()}"
    components = [c.to_dict() for c in _collect_components(distribution)]
    return {
        "bomFormat": _BOM_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "sealward-sbom",
                        "version": _installed_version(DEFAULT_DISTRIBUTION) or "0.0.0",
                    }
                ]
            },
            "component": _root_component(distribution),
        },
        "components": components,
    }


def render_sbom_json(
    distribution: str = DEFAULT_DISTRIBUTION,
    *,
    serial_number: str | None = None,
    timestamp: datetime | None = None,
    indent: int = 2,
) -> str:
    """Return :func:`build_sbom` rendered as a deterministic JSON string."""
    return json.dumps(
        build_sbom(distribution, serial_number=serial_number, timestamp=timestamp),
        indent=indent,
        sort_keys=False,
    )
