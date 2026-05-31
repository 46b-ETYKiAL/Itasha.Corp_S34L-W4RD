"""Tests for the key-custody resolver — handles only, never key values.

These tests assert the load-bearing custody guarantees:

* :class:`ResolvedHandle` carries the (non-secret) HANDLE, never private-key
  bytes — the model has no field that could hold a key value.
* Optional cloud / HSM providers degrade gracefully to ``available=False`` when
  their SDK is absent (the ``hsm_backend_unavailable`` fork) — never a raise,
  never a fake success.
* The inline-key-material tripwire rejects PEM blocks, key-container paths,
  and secret-value assignments at the schema boundary so a handle string can
  never smuggle key material into a :class:`ResolvedHandle`.
* The prod profile rejects a ``LOCAL_FILE`` handle (CA/B Forum CSC-17).

No test writes a real secret; the local-file provider touches only a synthetic
PUBLIC-key marker under ``tmp_path``.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sealward.config_schema import (
    CustodyProvider,
    KeyHandleRef,
    Profile,
    reject_inline_key_material,
)
from sealward.keycustody.resolver import (
    CustodyResolver,
    LocalFileProvider,
    ResolvedHandle,
    get_provider,
)

# --- ResolvedHandle never holds key material ---------------------------------


def test_resolved_handle_has_no_key_value_field() -> None:
    """The capability descriptor carries a handle, never a private-key value."""
    fields = set(ResolvedHandle.model_fields)
    assert fields == {"provider", "handle", "available", "usable", "detail"}
    # None of the fields is a key/secret/value-bearing slot.
    for name in ("key", "private_key", "secret", "value", "material", "pem"):
        assert name not in fields


def test_resolved_handle_carries_only_the_handle_string() -> None:
    """A resolved handle round-trips the opaque handle, not any key bytes."""
    rh = ResolvedHandle(
        provider=CustodyProvider.AWS_KMS,
        handle="arn:aws:kms:us-east-1:111122223333:key/abc",
        available=True,
        usable=True,
    )
    assert rh.handle == "arn:aws:kms:us-east-1:111122223333:key/abc"
    assert "PRIVATE KEY" not in rh.model_dump_json()


# --- local-file provider: PUBLIC-key marker only -----------------------------


def test_local_file_provider_usable_when_public_marker_present(tmp_path) -> None:
    """A present ``<ref>.pub`` marks the handle usable — no private bytes read."""
    pub = tmp_path / "devkey.pub"
    pub.write_text("", encoding="utf-8")  # synthetic public marker, no secret
    resolved = LocalFileProvider().resolve_handle(str(tmp_path / "devkey"))
    assert resolved.usable is True
    assert resolved.provider is CustodyProvider.LOCAL_FILE


def test_local_file_provider_not_usable_when_marker_absent(tmp_path) -> None:
    """Absent public marker → handle resolves but is not usable (honest)."""
    resolved = LocalFileProvider().resolve_handle(str(tmp_path / "missing"))
    assert resolved.usable is False
    assert resolved.available is True
    assert resolved.detail is not None


# --- optional cloud/HSM providers degrade gracefully -------------------------


@pytest.mark.parametrize(
    "provider_kind",
    [
        CustodyProvider.PKCS11,
        CustodyProvider.WINDOWS_CNG,
        CustodyProvider.AZURE_KEY_VAULT,
        CustodyProvider.AWS_KMS,
        CustodyProvider.GCP_KMS,
        CustodyProvider.HASHICORP_VAULT,
    ],
)
def test_optional_sdk_provider_degrades_without_raising(provider_kind) -> None:
    """An optional-SDK provider whose module is absent reports unavailable.

    The resolver must never raise on a missing SDK — it degrades to
    ``available=False`` / ``usable=False`` with a structured detail. We force
    the SDK-absent path by pointing the provider at a module that cannot import.
    """
    provider = get_provider(provider_kind)
    # Point the optional module at a guaranteed-absent name to exercise the
    # ImportError degrade path deterministically (no real SDK required).
    provider._module = "sealward._definitely_not_installed_sdk_xyz"  # type: ignore[attr-defined]
    assert provider.is_available() is False
    resolved = provider.resolve_handle("some-handle-ref")
    assert resolved.available is False
    assert resolved.usable is False
    assert resolved.detail is not None


def test_resolver_unavailable_provider_yields_structured_descriptor() -> None:
    """An unavailable provider yields a structured unusable handle, not a raise."""

    class _AlwaysUnavailable(LocalFileProvider):
        kind = CustodyProvider.AWS_KMS

        def is_available(self) -> bool:
            return False

    import sealward.keycustody.resolver as mod

    original = mod._PROVIDERS[CustodyProvider.AWS_KMS]
    mod._PROVIDERS[CustodyProvider.AWS_KMS] = _AlwaysUnavailable  # type: ignore[assignment]
    try:
        ref = KeyHandleRef(provider=CustodyProvider.AWS_KMS, ref="arn:aws:kms:x:y:key/z")
        resolved = CustodyResolver().resolve(ref, profile=Profile.PROD)
        assert resolved.available is False
        assert resolved.usable is False
    finally:
        mod._PROVIDERS[CustodyProvider.AWS_KMS] = original


# --- prod profile rejects LOCAL_FILE handles (CA/B CSC-17) --------------------


def test_prod_profile_rejects_local_file_handle() -> None:
    """In prod, a LOCAL_FILE handle is rejected as unusable (hardware-key rule)."""
    ref = KeyHandleRef(provider=CustodyProvider.LOCAL_FILE, ref="dev/local/devkey")
    resolved = CustodyResolver().resolve(ref, profile=Profile.PROD)
    assert resolved.usable is False
    assert resolved.detail is not None
    assert "CSC-17" in resolved.detail or "prod" in resolved.detail.lower()


# --- inline-key-material tripwire --------------------------------------------


def test_tripwire_rejects_pem_private_key_block() -> None:
    """A pasted PEM private-key block is rejected before becoming a handle."""
    pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
    with pytest.raises(ValueError, match=r"(?i)pem|key"):
        reject_inline_key_material(pem)


def test_tripwire_rejects_key_container_path() -> None:
    """A handle pointing at a private-key container extension is rejected."""
    for bad in ("certs/release.p12", "store.jks", "key.pem", "appstore.p8"):
        with pytest.raises(ValueError):
            reject_inline_key_material(bad)


def test_tripwire_rejects_secret_assignment_shape() -> None:
    """A pasted secret VALUE assignment is rejected."""
    with pytest.raises(ValueError, match=r"(?i)secret|value"):
        reject_inline_key_material("MATCH_PASSWORD=hunter2supersecret")


def test_key_handle_ref_rejects_inline_material_at_schema_boundary() -> None:
    """KeyHandleRef validation rejects an inline-key ``ref`` (defense in depth)."""
    with pytest.raises(ValidationError):
        KeyHandleRef(provider=CustodyProvider.LOCAL_FILE, ref="release.p12")


def test_os_keychain_provider_unavailable_when_no_cli(monkeypatch) -> None:
    """OsKeychainProvider degrades when no keychain CLI is on PATH."""
    import sealward.keycustody.resolver as mod
    from sealward.keycustody.resolver import OsKeychainProvider

    monkeypatch.setattr(mod.shutil, "which", lambda _tool: None)
    provider = OsKeychainProvider()
    assert provider.is_available() is False
    resolved = provider.resolve_handle("keychain-item")
    assert resolved.available is False
    assert resolved.usable is False


def test_os_keychain_provider_usable_when_cli_present(monkeypatch) -> None:
    """OsKeychainProvider reports the handle reachable when a keychain CLI exists."""
    import sealward.keycustody.resolver as mod
    from sealward.keycustody.resolver import OsKeychainProvider

    monkeypatch.setattr(
        mod.shutil, "which", lambda tool: "/usr/bin/security" if tool == "security" else None
    )
    resolved = OsKeychainProvider().resolve_handle("Developer ID Application")
    assert resolved.available is True
    assert resolved.usable is True


def test_base_provider_hooks_are_abstract() -> None:
    """The base provider hooks raise NotImplementedError (subclasses override)."""
    from sealward.keycustody.resolver import _Provider

    base = _Provider()
    with pytest.raises(NotImplementedError):
        base.is_available()
    with pytest.raises(NotImplementedError):
        base.resolve_handle("x")


def test_generate_dev_key_writes_public_marker_only(tmp_path) -> None:
    """generate_dev_key creates a PUBLIC marker (never private bytes) → usable."""
    key = tmp_path / "devkey"
    resolved = CustodyResolver().generate_dev_key(key)
    assert resolved.usable is True
    pub = tmp_path / "devkey.pub"
    assert pub.exists()
    # Only an empty public marker — no private-key material was written.
    assert pub.read_text(encoding="utf-8") == ""


def test_generate_dev_key_honours_env_dir_override(tmp_path, monkeypatch) -> None:
    """SEALWARD_DEV_KEY_DIR redirects the public marker parent directory."""
    target_dir = tmp_path / "devkeys"
    monkeypatch.setenv("SEALWARD_DEV_KEY_DIR", str(target_dir))
    resolved = CustodyResolver().generate_dev_key(tmp_path / "k")
    assert resolved.usable is True
    assert (target_dir / "k.pub").exists()


def test_resolver_local_file_dev_profile_resolves(tmp_path) -> None:
    """Dev profile resolves a LOCAL_FILE handle through the provider registry."""
    pub = tmp_path / "dev.pub"
    pub.write_text("", encoding="utf-8")
    ref = KeyHandleRef(provider=CustodyProvider.LOCAL_FILE, ref=str(tmp_path / "dev"))
    resolved = CustodyResolver().resolve(ref, profile=Profile.DEV)
    assert resolved.usable is True


def test_get_provider_returns_fresh_instance() -> None:
    """get_provider yields a provider instance for each known kind."""
    for kind in CustodyProvider:
        provider = get_provider(kind)
        assert provider.kind is kind


def test_tripwire_accepts_legitimate_handles() -> None:
    """Legitimate custody HANDLES pass the tripwire unchanged."""
    handles = [
        "pkcs11:slot=0;object=signing-key",
        "arn:aws:kms:us-east-1:111122223333:key/abc-def",
        "https://vault.azure.net/keys/release-key",
        "Developer ID Application: Example Corp (TEAMID)",
    ]
    for h in handles:
        assert reject_inline_key_material(h) == h
