"""Declarative signing-config schema (the signing manifest) — handles only.

This module defines the Pydantic model tree the orchestrator loads from a YAML
or TOML manifest. The whole point of the schema is that it carries **only key
HANDLES / URIs**, never inline key material. Two layers enforce this:

1. The :class:`KeyHandleRef` type models a custody reference as a
   ``provider`` + ``ref`` (slot / ARN / URI / path / container) pair. There is
   no field anywhere in the tree that accepts a private-key *value*.
2. A regex tripwire (:func:`reject_inline_key_material`) runs on every
   handle-bearing string. It rejects PEM key blocks, PKCS#12 magic, raw base64
   key blobs, and the ``MATCH_PASSWORD`` secret-shape — so a manifest that
   pastes a ``.p12`` path-as-value, a PEM block, or a password is rejected at
   parse time.

``CONTRACT_VERSION`` is bumped for any schema change; per the cross-repo
contract, schema changes fork to a v2 model rather than mutating v1.
"""

from __future__ import annotations

import enum
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "CONTRACT_VERSION",
    "KeyHandleRef",
    "Platform",
    "Profile",
    "SigningConfig",
    "SigningTarget",
    "TimestampAuthority",
    "reject_inline_key_material",
]

CONTRACT_VERSION = 1
"""Schema contract version. Bump on any change; fork to a v2 model, never mutate v1."""


class Platform(enum.StrEnum):
    """Target platform — selects the per-platform signing backend."""

    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"


class Profile(enum.StrEnum):
    """Signing profile — separates dev (self-signed / local) from prod (HSM/KMS)."""

    DEV = "dev"
    PROD = "prod"


class CustodyProvider(enum.StrEnum):
    """Key-custody provider kind a :class:`KeyHandleRef` resolves through."""

    LOCAL_FILE = "local_file"
    OS_KEYCHAIN = "os_keychain"
    PKCS11 = "pkcs11"
    WINDOWS_CNG = "windows_cng"
    AZURE_KEY_VAULT = "azure_key_vault"
    AWS_KMS = "aws_kms"
    GCP_KMS = "gcp_kms"
    HASHICORP_VAULT = "hashicorp_vault"


# --- Inline-key-material tripwire --------------------------------------------

# Patterns that indicate a STRING is (or contains) actual key material rather
# than a handle. Any match is a hard rejection at parse time.
_PEM_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |)?PRIVATE KEY-----",
)
_PEM_CERT_KEY = re.compile(r"-----BEGIN (?:CERTIFICATE|PGP PRIVATE KEY BLOCK)-----")
# PKCS#12 / PFX files start with the DER SEQUENCE 0x30 0x82; their textual
# magic when pasted is rare, so we instead reject obvious base64 key blobs.
_LONG_BASE64_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{60,}={0,2})")
# Secret-VALUE shapes (not handles): match-store passwords, raw fastlane secret.
_SECRET_ASSIGNMENT = re.compile(
    r"\b(?:MATCH_PASSWORD|KEY_PASSWORD|KEYSTORE_PASSWORD|P12_PASSWORD)\s*[=:]\s*\S+",
    re.IGNORECASE,
)
# File extensions that are key-material containers — a handle must never point
# at one as an inline *value* (a path handle to a local public key is fine, but
# private-key container extensions are rejected to keep the public repo safe).
_KEY_CONTAINER_EXT = re.compile(
    r"\.(?:p12|pfx|pem|key|keystore|jks|mobileprovision|p8|cer)\b",
    re.IGNORECASE,
)


def reject_inline_key_material(value: str, *, field_name: str = "value") -> str:
    """Raise ``ValueError`` if ``value`` looks like inline key material.

    Args:
        value: The candidate handle / reference string.
        field_name: Field name used in the raised error message.

    Returns:
        ``value`` unchanged when it passes every tripwire.

    Raises:
        ValueError: When the string matches a PEM block, a long base64 key
            blob, a secret-assignment shape, or a private-key container path.
    """
    if _PEM_BLOCK.search(value) or _PEM_CERT_KEY.search(value):
        raise ValueError(f"{field_name}: inline PEM key/cert material is forbidden — use a handle")
    if _SECRET_ASSIGNMENT.search(value):
        raise ValueError(
            f"{field_name}: inline secret value is forbidden — reference by env-var name only"
        )
    if _KEY_CONTAINER_EXT.search(value):
        raise ValueError(
            f"{field_name}: a private-key container path "
            "(.p12/.pfx/.pem/.key/.keystore/.jks/.p8/.cer/.mobileprovision) is "
            "forbidden as a value — resolve key material through a custody provider handle"
        )
    if _LONG_BASE64_BLOB.fullmatch(value.strip()):
        raise ValueError(f"{field_name}: raw base64 key blob is forbidden — use a handle")
    return value


# --- Schema models -----------------------------------------------------------


class KeyHandleRef(BaseModel):
    """A reference to a signing key by HANDLE — never a key value.

    The ``ref`` is interpreted by the custody resolver per ``provider``:
    a PKCS#11 slot label, a KMS ARN, a Key Vault URI, a CNG container name, a
    Vault path, an OS-keychain item name, or (dev only) a LOCAL public-key path.
    """

    model_config = ConfigDict(frozen=True)

    provider: CustodyProvider = Field(description="Custody provider kind.")
    ref: str = Field(
        min_length=1,
        description="Opaque handle (slot / ARN / URI / container / path / keychain item).",
    )

    @field_validator("ref")
    @classmethod
    def _no_inline_key(cls, v: str) -> str:
        return reject_inline_key_material(v, field_name="key_handle.ref")


class TimestampAuthority(BaseModel):
    """RFC-3161 timestamp-authority endpoint (with fallback ordering via the list)."""

    model_config = ConfigDict(frozen=True)

    url: str = Field(description="RFC-3161 TSA URL (http/https).")

    @field_validator("url")
    @classmethod
    def _looks_like_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("timestamp_authority.url must be an http(s) URL")
        return v


class SigningTarget(BaseModel):
    """A single signing target: which platform, which artifacts, which key."""

    model_config = ConfigDict(frozen=True)

    platform: Platform = Field(description="Target platform → selects the backend.")
    artifact_glob: str = Field(
        min_length=1,
        description="Glob selecting artifacts to sign (e.g. 'dist/*.exe').",
    )
    key_handle: KeyHandleRef = Field(description="Key custody handle (never a value).")
    timestamp_authorities: list[TimestampAuthority] = Field(
        default_factory=list,
        description="Ordered RFC-3161 TSA fallback list (empty = no timestamping).",
    )
    notarization_profile: str | None = Field(
        default=None,
        description="Opaque notarization-profile ref (macOS/iOS); a name, never a credential.",
    )

    @field_validator("notarization_profile")
    @classmethod
    def _profile_not_secret(cls, v: str | None) -> str | None:
        if v is not None:
            return reject_inline_key_material(v, field_name="notarization_profile")
        return v


class SigningConfig(BaseModel):
    """Top-level signing manifest the orchestrator loads.

    Carries a contract version, a dev/prod profile, and a list of targets. Every
    handle-bearing string in the tree has already passed the inline-key tripwire
    via the nested model validators by the time this model constructs.
    """

    model_config = ConfigDict(frozen=True)

    contract_version: int = Field(
        default=CONTRACT_VERSION,
        description="Schema contract version (must match the loader's CONTRACT_VERSION).",
    )
    profile: Profile = Field(
        default=Profile.DEV,
        description="dev (self-signed / local key) vs prod (HSM/KMS handle required).",
    )
    targets: list[SigningTarget] = Field(
        default_factory=list,
        description="Per-platform signing targets.",
    )

    @field_validator("contract_version")
    @classmethod
    def _version_supported(cls, v: int) -> int:
        if v != CONTRACT_VERSION:
            raise ValueError(
                f"unsupported contract_version {v}; this build supports {CONTRACT_VERSION}"
            )
        return v

    @model_validator(mode="after")
    def _prod_requires_hardware_handle(self) -> SigningConfig:
        """In the prod profile, local-file key handles are rejected (CA/B CSC-17).

        Production code-signing keys MUST live in FIPS 140-2 L2 / CC EAL4+
        hardware (CA/Browser Forum CSC-17). The dev profile permits a local
        self-signed key for testing; prod requires an HSM/KMS/keychain handle.
        """
        if self.profile is Profile.PROD:
            for target in self.targets:
                if target.key_handle.provider is CustodyProvider.LOCAL_FILE:
                    raise ValueError(
                        f"prod profile forbids LOCAL_FILE key handle for "
                        f"{target.platform.value}; use an HSM/KMS/keychain handle "
                        "(CA/Browser Forum CSC-17 hardware-key requirement)"
                    )
        return self
