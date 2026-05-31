"""SealWard — cross-platform code-signing orchestrator.

A single CLI + declarative config that delegates to the canonical per-platform
signing backend over a pluggable key-custody abstraction. Security derives from
private-key secrecy and HSM/KMS custody (Kerckhoffs's principle), never from
source obscurity — so this package's source is safe to publish publicly.

The package NEVER reads, stores, or commits key material: it resolves a key
HANDLE (PKCS#11 slot / Windows CNG / Azure Key Vault URI / AWS KMS ARN / GCP KMS
resource / HashiCorp Vault path) and lets the external custody store perform the
cryptographic operation.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
