"""SealWard orchestrator CLI — load config, resolve handles, dispatch, verify.

Engine-agnostic argparse CLI exposing three subcommands:

* ``probe``  — list the per-platform capability surface. Works with ZERO
  credentials: it reports tool + credential presence per backend without
  requiring either. This is the honest capability surface.
* ``sign``   — load a signing manifest, resolve each target's key handle via the
  custody layer, dispatch to the platform backend, and run verify-after-sign.
* ``verify`` — verify an existing signature on an artifact via the platform
  backend.

The orchestrator routes ``platform → backend`` purely through the
:class:`~sealward.backends.base.SignerBackend` Protocol and the backend
registry. No concrete backend is hard-imported here; backends register
themselves as the Phase 2-6 modules land. When no backend is registered for a
platform, the dispatch returns a structured ``SKIPPED_*`` outcome — never a
fabricated success and never a dormant/unreachable table entry (every
registered backend is reachable from this dispatch).

The CLI NEVER prints a key value: it prints handles, statuses, and verify
verdicts only. Config is loaded from YAML or TOML; both use stdlib-or-optional
parsers with graceful degradation.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

from sealward import __version__
from sealward.config_schema import (
    Platform,
    SigningConfig,
    SigningTarget,
)
from sealward.keycustody.resolver import CustodyResolver
from sealward.result import (
    SigningOutcome,
    SigningStatus,
    VerifyVerdict,
    outcome_counter,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sealward.backends.base import CapabilityReport, SignerBackend

__all__ = ["get_backend", "main", "registered_platforms"]


# --- Backend registry --------------------------------------------------------
#
# Backends (Phases 2-6) register a zero-arg factory here at import time. Until a
# platform's backend module lands, its slot is empty and the orchestrator emits
# a structured SKIPPED_TOOL_ABSENT outcome — the dispatch table never carries a
# dormant entry, and a missing backend never fabricates a SIGNED result.

_BACKEND_FACTORIES: dict[Platform, type[SignerBackend] | object] = {}


def register_backend(platform: Platform, factory: object) -> None:
    """Register a backend factory (zero-arg callable) for ``platform``."""
    _BACKEND_FACTORIES[platform] = factory


def get_backend(platform: Platform) -> SignerBackend | None:
    """Return a backend instance for ``platform``, or ``None`` if unregistered."""
    factory = _BACKEND_FACTORIES.get(platform)
    if factory is None:
        return None
    return factory()  # type: ignore[operator]


def registered_platforms() -> list[Platform]:
    """Return the platforms with a registered backend (sorted by value)."""
    return sorted(_BACKEND_FACTORIES.keys(), key=lambda p: p.value)


# --- Config loading ----------------------------------------------------------


def _load_config(path: Path) -> SigningConfig:
    """Load and validate a signing manifest from a YAML or TOML file.

    TOML uses stdlib ``tomllib``. YAML uses ``PyYAML`` when present; absence is a
    structured error (never a silent fallback to an empty config).
    """
    raw = path.read_bytes()
    suffix = path.suffix.lower()
    if suffix == ".toml":
        data = tomllib.loads(raw.decode("utf-8"))
    elif suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:  # structured, not silent
            raise SystemExit(
                f"cannot load YAML config {path}: PyYAML not installed; "
                "install it or use a .toml manifest"
            ) from exc
        data = yaml.safe_load(raw.decode("utf-8")) or {}
    else:
        raise SystemExit(f"unsupported config extension '{suffix}' (use .toml / .yaml / .yml)")
    return SigningConfig.model_validate(data)


# --- Dispatch ----------------------------------------------------------------


def _dispatch_sign(
    target: SigningTarget, config: SigningConfig, *, dry_run: bool
) -> SigningOutcome:
    """Resolve the target's key handle and dispatch a sign to its backend."""
    backend = get_backend(target.platform)
    if backend is None:
        return SigningOutcome(
            status=SigningStatus.SKIPPED_TOOL_ABSENT,
            backend=target.platform.value,
            artifact=target.artifact_glob,
            skipped_reason=f"no backend registered for platform {target.platform.value}",
        )

    resolved = CustodyResolver().resolve(target.key_handle, profile=config.profile)
    if not resolved.usable:
        return SigningOutcome(
            status=SigningStatus.SKIPPED_NO_CREDENTIAL,
            backend=backend.name,
            artifact=target.artifact_glob,
            key_handle=resolved.handle,
            skipped_reason=resolved.detail or "key handle not usable",
        )

    if dry_run:
        # A dry-run NEVER claims SIGNED — no real signature occurred. It reports
        # a skipped outcome carrying the would-sign capability in evidence.
        report = backend.capability_probe()
        return SigningOutcome(
            status=SigningStatus.SKIPPED_NO_CREDENTIAL,
            backend=backend.name,
            artifact=target.artifact_glob,
            key_handle=resolved.handle,
            verify_verdict=VerifyVerdict.NOT_RUN,
            skipped_reason="dry-run: no signature performed",
            evidence={
                "dry_run": True,
                "would_sign": report.can_sign,
                "tool": report.tool_name,
            },
        )

    return backend.sign(target)


def _cmd_probe(args: argparse.Namespace) -> int:
    """List per-platform capability — credential-free."""
    reports: list[CapabilityReport] = []
    platforms = [Platform(args.platform)] if args.platform else list(Platform)
    for platform in platforms:
        backend = get_backend(platform)
        if backend is None:
            payload = {
                "platform": platform.value,
                "backend": None,
                "registered": False,
                "tool_present": False,
                "credential_present": False,
                "can_sign": False,
                "detail": "no backend registered for this platform yet",
            }
        else:
            report = backend.capability_probe()
            payload = {**report.model_dump(mode="json"), "registered": True}
        reports.append(payload)  # type: ignore[arg-type]
    print(json.dumps({"capabilities": reports}, indent=2))
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    """Load config, dispatch each target, run verify-after-sign, emit JSON."""
    config = _load_config(Path(args.config))
    platform_filter = Platform(args.platform) if args.platform else None
    outcomes: list[SigningOutcome] = []
    for target in config.targets:
        if platform_filter and target.platform is not platform_filter:
            continue
        outcome = _dispatch_sign(target, config, dry_run=args.dry_run)
        outcome_counter.record(outcome)
        outcomes.append(outcome)
    print(json.dumps([json.loads(o.to_json()) for o in outcomes], indent=2))
    # Non-zero exit if any target FAILED (skips are not failures).
    return 1 if any(o.status is SigningStatus.FAILED for o in outcomes) else 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify an existing signature via the platform backend."""
    platform = Platform(args.platform)
    backend = get_backend(platform)
    if backend is None:
        outcome = SigningOutcome(
            status=SigningStatus.SKIPPED_TOOL_ABSENT,
            backend=platform.value,
            artifact=args.artifact,
            skipped_reason=f"no backend registered for platform {platform.value}",
        )
    else:
        outcome = backend.verify(Path(args.artifact))
    outcome_counter.record(outcome)
    print(outcome.to_json())
    ok = outcome.status is SigningStatus.VERIFIED or outcome.status.is_skipped
    return 0 if ok else 1


def _build_parser() -> argparse.ArgumentParser:
    """Build the argparse CLI surface."""
    parser = argparse.ArgumentParser(
        prog="sealward",
        description="Cross-platform code-signing orchestrator (keys never live here).",
    )
    parser.add_argument("--version", action="version", version=f"sealward {__version__}")
    platform_choices = [p.value for p in Platform]

    sub = parser.add_subparsers(dest="command", required=True)

    p_probe = sub.add_parser(
        "probe",
        help="List per-platform capability (works with ZERO credentials).",
    )
    p_probe.add_argument(
        "--platform",
        choices=platform_choices,
        default=None,
        help="Probe a single platform (default: all).",
    )
    p_probe.set_defaults(func=_cmd_probe)

    p_sign = sub.add_parser("sign", help="Sign artifacts per a manifest, then verify-after-sign.")
    p_sign.add_argument(
        "--config", required=True, help="Path to the signing manifest (.toml/.yaml)."
    )
    p_sign.add_argument(
        "--platform",
        choices=platform_choices,
        default=None,
        help="Restrict to a single platform's targets (default: all).",
    )
    p_sign.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve + probe without performing a real signature.",
    )
    p_sign.set_defaults(func=_cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify an existing signature on an artifact.")
    p_verify.add_argument("--platform", required=True, choices=platform_choices)
    p_verify.add_argument("--artifact", required=True, help="Path to the signed artifact.")
    p_verify.set_defaults(func=_cmd_verify)

    return parser


def _ensure_backends_registered() -> None:
    """Import the backends package so every backend self-registers.

    The concrete backend modules call :func:`register_backend` at import time, but
    nothing imports them implicitly. The orchestrator entry point triggers that
    wiring here. The import is local to ``main`` (not module-level) to avoid the
    import cycle: each backend module imports ``register_backend`` from this
    module, so a top-level ``import sealward.backends`` would be circular.
    """
    import sealward.backends  # noqa: F401 - side-effecting: fires register_backend(...)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    _ensure_backends_registered()
    parser = _build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
