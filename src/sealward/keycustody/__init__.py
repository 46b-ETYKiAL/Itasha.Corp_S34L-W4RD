"""Key-custody abstraction.

Resolves a key HANDLE (slot / ARN / URI / path) to a signing capability without
ever reading or returning a raw private key. The signing key material stays in
its external custody store (HSM / KMS / OS keychain / CI secret store); SealWard
only references it by handle.
"""

from __future__ import annotations

from sealward.keycustody.resolver import CustodyResolver, ResolvedHandle, get_provider

__all__ = ["CustodyResolver", "ResolvedHandle", "get_provider"]
