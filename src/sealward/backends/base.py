"""Abstract signer-backend contract + capability probe.

Every per-platform backend (Windows / macOS / Linux / Android / iOS — Phases
2-6) implements :class:`SignerBackend`. This module defines ONLY the contract
and the capability-report type; it contains no concrete backend and no
platform-specific import (so it stays importable on every OS).

The load-bearing honesty primitive is :meth:`SignerBackend.capability_probe`:
it detects whether the OS toolchain AND the operator credential are present
*without requiring them*. When either is absent, :meth:`SignerBackend.sign`
MUST return a ``SKIPPED_*`` :class:`~sealward.result.SigningOutcome` — it MUST
NEVER fabricate a ``SIGNED`` outcome. This is what lets the ``probe`` CLI
subcommand work with zero credentials and what makes a ``SIGNED`` result
trustworthy.

Verify-after-sign is mandatory: a backend that returns ``SIGNED`` MUST have run
its native verifier (signtool verify / codesign --verify / apksigner verify /
cosign verify) and recorded the verdict in
:attr:`~sealward.result.SigningOutcome.verify_verdict`. A backend that cannot
verify what it signed returns ``FAILED`` with the verify verdict ``FAILED`` —
it never silently trusts its own signing step.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pathlib import Path

    from sealward.config_schema import SigningTarget
    from sealward.result import SigningOutcome

__all__ = [
    "CapabilityReport",
    "SignerBackend",
    "SignerBackendABC",
]


class CapabilityReport(BaseModel):
    """Result of a credential-free capability probe.

    A probe NEVER requires a credential to run. It reports, separately:

    * whether the platform signing TOOL is installed (``tool_present``), and
    * whether the operator CREDENTIAL / key handle is resolvable
      (``credential_present``).

    Both must be true for a real sign to proceed; a backend maps the two
    absences to the two ``SKIPPED_*`` statuses
    (:attr:`~sealward.result.SigningStatus.SKIPPED_TOOL_ABSENT` /
    :attr:`~sealward.result.SigningStatus.SKIPPED_NO_CREDENTIAL`).
    """

    model_config = ConfigDict(frozen=True)

    backend: str = Field(description="Backend name (e.g. 'windows').")
    platform: str = Field(description="Target platform this backend serves.")
    tool_present: bool = Field(
        description="Whether the OS / OSS signing tool was detected on PATH.",
    )
    tool_name: str | None = Field(
        default=None,
        description="Name of the detected tool (e.g. 'signtool', 'osslsigncode').",
    )
    tool_version: str | None = Field(
        default=None,
        description="Detected tool version string (non-secret).",
    )
    credential_present: bool = Field(
        default=False,
        description="Whether the operator credential / key handle is resolvable.",
    )
    can_sign: bool = Field(
        default=False,
        description="True only when BOTH tool_present and credential_present hold.",
    )
    detail: str | None = Field(
        default=None,
        description="Human-readable probe detail (non-secret diagnostic).",
    )

    @classmethod
    def from_flags(
        cls,
        *,
        backend: str,
        platform: str,
        tool_present: bool,
        credential_present: bool,
        tool_name: str | None = None,
        tool_version: str | None = None,
        detail: str | None = None,
    ) -> CapabilityReport:
        """Build a report, deriving ``can_sign`` from the two presence flags."""
        return cls(
            backend=backend,
            platform=platform,
            tool_present=tool_present,
            tool_name=tool_name,
            tool_version=tool_version,
            credential_present=credential_present,
            can_sign=bool(tool_present and credential_present),
            detail=detail,
        )


@runtime_checkable
class SignerBackend(Protocol):
    """Structural contract every per-platform signing backend satisfies.

    Concrete backends (Phases 2-6) subclass :class:`SignerBackendABC` (which
    satisfies this Protocol) and implement the three abstract methods. The
    dispatch table in :mod:`sealward.cli` routes a target's platform to its
    backend purely through this surface — no concrete backend leaks into the
    orchestrator.
    """

    name: str
    """Stable backend identifier (e.g. 'windows', 'macos', 'linux')."""

    platform: str
    """The platform this backend serves (matches a ``config_schema.Platform`` value)."""

    def capability_probe(self) -> CapabilityReport:
        """Detect tool + credential presence WITHOUT requiring either.

        Returns a :class:`CapabilityReport`. NEVER raises and NEVER requires a
        credential to be present — this is the credential-free honesty surface
        the ``probe`` CLI subcommand relies on.
        """
        ...

    def sign(self, target: SigningTarget) -> SigningOutcome:
        """Sign the artifacts named by ``target`` and verify the result.

        Contract:

        * If the tool is absent → return ``SKIPPED_TOOL_ABSENT`` (never SIGNED).
        * If the credential / key handle is unresolvable →
          ``SKIPPED_NO_CREDENTIAL`` (never SIGNED).
        * On a real sign → run the native verifier and record
          ``verify_verdict``; return ``SIGNED`` only when the verifier passed.
        * On tool error → ``FAILED`` with the redacted error.

        NEVER raises; all failure modes map to a structured
        :class:`~sealward.result.SigningOutcome`.
        """
        ...

    def verify(self, artifact: Path) -> SigningOutcome:
        """Verify an existing signature on ``artifact``.

        Returns a :class:`~sealward.result.SigningOutcome` with status
        ``VERIFIED`` / ``FAILED`` (or ``SKIPPED_TOOL_ABSENT`` when the verifier
        tool is not installed). NEVER raises.
        """
        ...


class SignerBackendABC(abc.ABC):
    """Abstract base for concrete backends; satisfies :class:`SignerBackend`.

    Provides the ``name`` / ``platform`` attribute slots and declares the three
    abstract methods. Concrete subclasses (Phases 2-6) fill in the shell-out
    logic to the canonical per-platform tool.
    """

    #: Stable backend identifier — set by each concrete subclass.
    name: str = ""
    #: Platform served — set by each concrete subclass.
    platform: str = ""

    @abc.abstractmethod
    def capability_probe(self) -> CapabilityReport:
        """See :meth:`SignerBackend.capability_probe`."""
        raise NotImplementedError

    @abc.abstractmethod
    def sign(self, target: SigningTarget) -> SigningOutcome:
        """See :meth:`SignerBackend.sign`."""
        raise NotImplementedError

    @abc.abstractmethod
    def verify(self, artifact: Path) -> SigningOutcome:
        """See :meth:`SignerBackend.verify`."""
        raise NotImplementedError
