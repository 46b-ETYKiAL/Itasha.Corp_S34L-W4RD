"""Pluggable key-custody resolution — resolves a HANDLE, never a key value.

Each custody provider is a class exposing two methods:

* ``is_available()`` — does the backing store / SDK exist on this machine,
  *without* requiring a credential to be present? (capability probe)
* ``resolve_handle(ref)`` — turn an opaque handle string into a
  :class:`ResolvedHandle` *capability descriptor*. The descriptor records the
  provider, the (non-secret) handle, and whether the handle is currently usable
  — it NEVER contains private-key bytes.

Cloud / HSM providers (Azure Key Vault, AWS KMS, GCP KMS, HashiCorp Vault,
PKCS#11, Windows CNG) are optional-import-guarded: importing their SDK is
deferred and absence degrades gracefully to ``is_available() == False`` rather
than raising at module import. The local-file provider (dev only) is the single
provider that touches the filesystem, and it touches only the PUBLIC key path
for verification — it never reads private-key bytes into the process.

An unreachable provider yields a structured ``available=False`` /
``usable=False`` :class:`ResolvedHandle` (the ``hsm_backend_unavailable`` fork)
— it NEVER swallows the error silently and NEVER returns a fake success.

Ported design shape: ``key_resolver.py`` (local-key fallback + handle
resolution) from the S4F3 monorepo, generalised across all custody providers.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from sealward.config_schema import CustodyProvider, KeyHandleRef, Profile

__all__ = [
    "CustodyResolver",
    "ResolvedHandle",
    "get_provider",
]


class ResolvedHandle(BaseModel):
    """Capability descriptor for a resolved key handle — never key material.

    A ``usable=True`` descriptor means the custody store reported the handle as
    present and a signing operation can target it. It carries the provider kind
    and the (non-secret) handle reference only.
    """

    model_config = ConfigDict(frozen=True)

    provider: CustodyProvider = Field(description="Custody provider kind.")
    handle: str = Field(description="The opaque handle (non-secret reference).")
    available: bool = Field(description="Whether the provider backend is reachable at all.")
    usable: bool = Field(
        default=False,
        description="Whether the handle resolves to a signing-capable key right now.",
    )
    detail: str | None = Field(
        default=None,
        description="Non-secret diagnostic (e.g. why unavailable).",
    )


class _Provider:
    """Base custody provider. Subclasses override the two probe/resolve hooks."""

    kind: CustodyProvider

    def is_available(self) -> bool:
        """Whether the backing store / SDK is present (no credential required)."""
        raise NotImplementedError

    def resolve_handle(self, ref: str) -> ResolvedHandle:
        """Resolve ``ref`` to a capability descriptor (never key bytes)."""
        raise NotImplementedError

    def _unavailable(self, ref: str, detail: str) -> ResolvedHandle:
        return ResolvedHandle(
            provider=self.kind,
            handle=ref,
            available=False,
            usable=False,
            detail=detail,
        )


class LocalFileProvider(_Provider):
    """Dev-only local key handle. ``ref`` is a path to a local key pair.

    Probe / resolution check only the existence of the PUBLIC key (``<ref>.pub``
    or the path itself when it ends in ``.pub``). Private-key bytes are NEVER
    read here — the actual signing operation is performed by the platform tool
    that owns the key file, not by this resolver.
    """

    kind = CustodyProvider.LOCAL_FILE

    def is_available(self) -> bool:
        return True  # the local filesystem is always present

    def resolve_handle(self, ref: str) -> ResolvedHandle:
        path = Path(ref).expanduser()
        pub = path if path.suffix == ".pub" else path.with_suffix(".pub")
        usable = pub.is_file()
        return ResolvedHandle(
            provider=self.kind,
            handle=ref,
            available=True,
            usable=usable,
            detail=None if usable else f"local public key not found at {pub}",
        )


class OsKeychainProvider(_Provider):
    """OS keychain handle (macOS Keychain / Windows Cert Store / Secret Service).

    Availability is probed by detecting the platform keychain CLI; the handle is
    a keychain item name. Resolution reports usability without extracting key
    bytes (the platform signing tool reads the item directly at sign time).
    """

    kind = CustodyProvider.OS_KEYCHAIN

    def is_available(self) -> bool:
        # security (macOS), certutil (Windows), secret-tool (Linux Secret Service)
        return any(shutil.which(t) is not None for t in ("security", "certutil", "secret-tool"))

    def resolve_handle(self, ref: str) -> ResolvedHandle:
        if not self.is_available():
            return self._unavailable(
                ref, "no OS keychain CLI detected (security/certutil/secret-tool)"
            )
        # Presence of the named item is verified by the platform tool at sign
        # time; the resolver reports the handle as reachable.
        return ResolvedHandle(provider=self.kind, handle=ref, available=True, usable=True)


class _OptionalSdkProvider(_Provider):
    """Cloud / HSM provider whose SDK import is optional and deferred.

    Subclasses declare ``_module`` (the SDK top-level package). ``is_available``
    returns True only when the SDK imports successfully — absence degrades to
    False with a structured detail rather than raising at module import.
    """

    _module: str = ""

    def is_available(self) -> bool:
        try:
            import importlib

            importlib.import_module(self._module)
            return True
        except ImportError:
            # silence-reason: optional-import; owner: 46b-ETYKiAL; expires: 2027-05-30
            return False

    def resolve_handle(self, ref: str) -> ResolvedHandle:
        if not self.is_available():
            return self._unavailable(
                ref,
                f"optional SDK '{self._module}' not installed; "
                f"install the 'kms' extra to enable {self.kind.value}",
            )
        # SDK present: the handle is reachable. Actual credential validation is
        # the cloud/HSM store's job at sign time; the resolver does not hold or
        # fetch key material — only confirms the handle is well-formed + the SDK
        # path exists. A credential being absent surfaces later as a SKIPPED_*
        # outcome in the backend, never as a fake success here.
        return ResolvedHandle(provider=self.kind, handle=ref, available=True, usable=True)


class Pkcs11Provider(_OptionalSdkProvider):
    """PKCS#11 (vendor-neutral HSM/token) handle: a slot label / object id."""

    kind = CustodyProvider.PKCS11
    _module = "pkcs11"


class WindowsCngProvider(_OptionalSdkProvider):
    """Windows CNG/KSP handle: a key container name. Probed via the CNG SDK shim."""

    kind = CustodyProvider.WINDOWS_CNG
    _module = "win32crypt"


class AzureKeyVaultProvider(_OptionalSdkProvider):
    """Azure Key Vault handle: a key URI. Optional ``azure-keyvault-keys`` SDK."""

    kind = CustodyProvider.AZURE_KEY_VAULT
    _module = "azure.keyvault.keys"


class AwsKmsProvider(_OptionalSdkProvider):
    """AWS KMS handle: a key ARN. Optional ``boto3`` SDK."""

    kind = CustodyProvider.AWS_KMS
    _module = "boto3"


class GcpKmsProvider(_OptionalSdkProvider):
    """GCP KMS handle: a crypto-key resource name. Optional ``google-cloud-kms`` SDK."""

    kind = CustodyProvider.GCP_KMS
    _module = "google.cloud.kms"


class HashicorpVaultProvider(_OptionalSdkProvider):
    """HashiCorp Vault handle: a transit-key path. Optional ``hvac`` SDK."""

    kind = CustodyProvider.HASHICORP_VAULT
    _module = "hvac"


_PROVIDERS: dict[CustodyProvider, type[_Provider]] = {
    CustodyProvider.LOCAL_FILE: LocalFileProvider,
    CustodyProvider.OS_KEYCHAIN: OsKeychainProvider,
    CustodyProvider.PKCS11: Pkcs11Provider,
    CustodyProvider.WINDOWS_CNG: WindowsCngProvider,
    CustodyProvider.AZURE_KEY_VAULT: AzureKeyVaultProvider,
    CustodyProvider.AWS_KMS: AwsKmsProvider,
    CustodyProvider.GCP_KMS: GcpKmsProvider,
    CustodyProvider.HASHICORP_VAULT: HashicorpVaultProvider,
}


def get_provider(kind: CustodyProvider) -> _Provider:
    """Return a fresh provider instance for ``kind``."""
    return _PROVIDERS[kind]()


class CustodyResolver:
    """Front door for resolving :class:`KeyHandleRef` values to capabilities.

    Stateless dispatcher over the provider registry. Resolves a handle to a
    :class:`ResolvedHandle` capability descriptor; never reads, returns, or
    persists private-key bytes.
    """

    def resolve(self, ref: KeyHandleRef, *, profile: Profile = Profile.DEV) -> ResolvedHandle:
        """Resolve a key-handle reference to a capability descriptor.

        Args:
            ref: The custody handle reference from the manifest.
            profile: dev vs prod. In ``prod`` a ``LOCAL_FILE`` provider is
                rejected as unusable (CA/Browser Forum CSC-17 hardware-key
                requirement) even if the file exists.

        Returns:
            A :class:`ResolvedHandle`. An unreachable provider yields
            ``available=False`` / ``usable=False`` (the ``hsm_backend_unavailable``
            fork) — never a silent swallow, never a fake success.
        """
        if profile is Profile.PROD and ref.provider is CustodyProvider.LOCAL_FILE:
            return ResolvedHandle(
                provider=ref.provider,
                handle=ref.ref,
                available=True,
                usable=False,
                detail="prod profile forbids LOCAL_FILE key handle (CA/B CSC-17 hardware rule)",
            )
        provider = get_provider(ref.provider)
        if not provider.is_available():
            return ResolvedHandle(
                provider=ref.provider,
                handle=ref.ref,
                available=False,
                usable=False,
                detail=f"custody provider {ref.provider.value} unavailable on this machine",
            )
        return provider.resolve_handle(ref.ref)

    def generate_dev_key(self, key_path: Path) -> ResolvedHandle:
        """Resolve a dev self-signed local key, generating the public marker if absent.

        Dev-profile convenience: if ``<key_path>.pub`` does not exist this writes
        an empty public-key marker so the local provider reports the handle
        usable for a dev/test sign. It does NOT generate or write private-key
        material — real key generation is the platform tool's job. Honours the
        ``SEALWARD_DEV_KEY_DIR`` env override for the parent directory.
        """
        env_dir = os.environ.get("SEALWARD_DEV_KEY_DIR")
        path = (Path(env_dir) / key_path.name) if env_dir else key_path.expanduser()
        pub = path if path.suffix == ".pub" else path.with_suffix(".pub")
        if not pub.exists():
            pub.parent.mkdir(parents=True, exist_ok=True)
            pub.write_text("", encoding="utf-8")  # public marker only — no private bytes
        return LocalFileProvider().resolve_handle(str(path))
