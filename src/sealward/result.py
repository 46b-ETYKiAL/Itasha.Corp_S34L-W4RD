"""Structured signing/verification outcome model — raw-secret-free by construction.

This module defines :class:`SigningOutcome`, the single typed result every
backend ``sign`` / ``verify`` call and every CLI subcommand returns. The model
is designed so that **no field can ever hold key material**:

* The only key-identifying field is :attr:`SigningOutcome.key_handle` — a
  *handle string* (a PKCS#11 slot label, a KMS ARN, a Key Vault URI, a CNG
  container name, a Vault path, or a local public-key path). It is NEVER the
  private key value. The :class:`config_schema.SigningConfig` validators reject
  any handle that looks like inline key material before a handle ever reaches a
  :class:`SigningOutcome`.
* The :attr:`SigningOutcome.evidence` dict carries verification verdicts, tool
  versions, timestamp-authority URLs, and digests — aggregate, PII-free, and
  redacted by the populating backend. It is a free-form mapping by type but is
  never used to smuggle secrets: backends populate it only with non-secret
  metadata.

The honesty primitive of the whole system lives in :class:`SigningStatus`:
when a toolchain or operator credential is absent, a backend returns a
``SKIPPED_*`` status — it NEVER fabricates ``SIGNED``. A ``SigningOutcome`` is
therefore an *auditable* record: ``SIGNED`` always means a real signature was
produced and (per the base-backend contract) verified.

Ported design shape: ``cosign_signer.SigningOutcome`` from the S4F3 monorepo
(structured status + signing method + identity + error, never raises). This
generalises it across all five platforms with an explicit skipped/blocked
taxonomy.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "SigningOutcome",
    "SigningStatus",
    "VerifyVerdict",
    "outcome_counter",
]


class SigningStatus(enum.StrEnum):
    """Terminal status of a signing or verification operation.

    The ``SKIPPED_*`` members are the load-bearing honesty primitive: a backend
    whose tool or credential is absent returns a skipped status rather than a
    fabricated ``SIGNED``. ``FAILED`` means the operation was attempted and the
    tool reported an error (distinct from skipped, which means it was never
    attempted because a precondition was absent).
    """

    SIGNED = "signed"
    """A real signature was produced and (per contract) verified."""

    VERIFIED = "verified"
    """An existing signature was checked and found valid."""

    SKIPPED_NO_CREDENTIAL = "skipped_no_credential"
    """The required operator credential / key handle was not resolvable."""

    SKIPPED_TOOL_ABSENT = "skipped_tool_absent"
    """The OS / OSS signing tool for this platform is not installed."""

    FAILED = "failed"
    """The operation was attempted and the tool reported a failure."""

    @property
    def is_skipped(self) -> bool:
        """True for any ``SKIPPED_*`` status."""
        return self in (
            SigningStatus.SKIPPED_NO_CREDENTIAL,
            SigningStatus.SKIPPED_TOOL_ABSENT,
        )

    @property
    def is_success(self) -> bool:
        """True only for genuine ``SIGNED`` / ``VERIFIED`` outcomes."""
        return self in (SigningStatus.SIGNED, SigningStatus.VERIFIED)


class VerifyVerdict(enum.StrEnum):
    """Explicit verify-after-sign verdict carried alongside the status.

    A backend that signs MUST run verification and record the verdict here so a
    ``SIGNED`` status is never trusted on a backend's bare word (anti
    corrupt-success; PAE procedural-integrity floor).
    """

    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"
    """Verification was not applicable (e.g. a pure ``verify`` of an absent tool)."""


class SigningOutcome(BaseModel):
    """Typed, JSON-serialisable, raw-secret-free result of a sign/verify call.

    The model is ``frozen`` so a populated outcome cannot be mutated after a
    backend returns it. Every field is non-secret by construction; see the
    module docstring for the no-key-material guarantee.
    """

    model_config = ConfigDict(frozen=True, use_enum_values=False)

    status: SigningStatus = Field(
        description="Terminal status of the operation (SIGNED / VERIFIED / SKIPPED_* / FAILED).",
    )
    backend: str = Field(
        description="Name of the backend that produced this outcome (e.g. 'windows', 'macos').",
    )
    artifact: str | None = Field(
        default=None,
        description="Path of the artifact operated on (a path, never file contents).",
    )
    algorithm: str | None = Field(
        default=None,
        description="Signature scheme used (e.g. 'authenticode', 'apk-v2+v3', 'ed25519').",
    )
    timestamp_authority: str | None = Field(
        default=None,
        description="RFC-3161 timestamp-authority URL applied (when timestamping ran).",
    )
    key_handle: str | None = Field(
        default=None,
        description=(
            "Key HANDLE used (PKCS#11 slot / KMS ARN / Key Vault URI / CNG "
            "container / Vault path / local public-key path). NEVER the private "
            "key value."
        ),
    )
    verify_verdict: VerifyVerdict = Field(
        default=VerifyVerdict.NOT_RUN,
        description="Explicit verify-after-sign verdict (anti corrupt-success).",
    )
    skipped_reason: str | None = Field(
        default=None,
        description="Structured reason a SKIPPED_* status was returned.",
    )
    blocked_reason: str | None = Field(
        default=None,
        description="Structured reason an operation was blocked (e.g. policy fork).",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp the outcome was produced.",
    )
    evidence: dict[str, str | int | bool | None] = Field(
        default_factory=dict,
        description=(
            "Aggregate, PII-free, non-secret metadata: verify verdicts, tool "
            "versions, digests, TSA URLs. NEVER key material or file contents."
        ),
    )
    error: str | None = Field(
        default=None,
        description="Error message when status is FAILED (tool stderr, redacted of secrets).",
    )

    def to_json(self) -> str:
        """Return a deterministic JSON serialisation of this outcome."""
        return self.model_dump_json(indent=2)


class _OutcomeCounter:
    """Aggregate-only, in-process counter of outcomes by status.

    PII-free telemetry: it records ONLY the count per status name. No artifact
    path, no key handle, no identity is retained. Honours an opt-out so callers
    can disable accumulation entirely.
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._enabled = True

    def record(self, outcome: SigningOutcome) -> None:
        """Increment the counter for ``outcome.status`` (no PII retained)."""
        if not self._enabled:
            return
        key = outcome.status.value
        self._counts[key] = self._counts.get(key, 0) + 1

    def snapshot(self) -> dict[str, int]:
        """Return a copy of the current aggregate counts."""
        return dict(self._counts)

    def reset(self) -> None:
        """Clear all accumulated counts."""
        self._counts.clear()

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable accumulation (telemetry opt-out)."""
        self._enabled = enabled


outcome_counter = _OutcomeCounter()
"""Process-wide aggregate-only outcome counter (PII-free)."""
