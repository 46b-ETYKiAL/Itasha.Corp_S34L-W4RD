"""Own-release provenance.

Sigstore keyless signing (Fulcio + Rekor), CycloneDX SBOM, and SLSA provenance
for SealWard's OWN releases — so consumers can verify the signer binary they pin
was built and published by SealWard's CI identity through an auditable
transparency log.
"""

from __future__ import annotations

from sealward.provenance.sbom import build_sbom, render_sbom_json
from sealward.provenance.sigstore_release import (
    SigstoreReleaseSigner,
    sigstore_available,
)
from sealward.provenance.slsa import build_slsa_provenance, render_slsa_json

__all__ = [
    "SigstoreReleaseSigner",
    "build_sbom",
    "build_slsa_provenance",
    "render_sbom_json",
    "render_slsa_json",
    "sigstore_available",
]
