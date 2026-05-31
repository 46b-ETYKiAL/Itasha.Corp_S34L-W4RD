"""Per-platform signing backends.

Each backend shells out to the canonical OS / OSS signing tool for its platform
(Windows: SignTool/osslsigncode/jsign; macOS/iOS: codesign/notarytool/stapler;
Linux: gpg/minisign/cosign; Android: apksigner/jarsigner) and emits a structured
SigningOutcome. A backend NEVER fakes a signature: when its tool or the required
credential is absent it emits a structured skipped/blocked reason.

Importing this package is what *wires* the dispatch table: each backend module
calls :func:`sealward.cli.register_backend` at import time, but those modules are
not auto-imported by the Python machinery. The eager imports below fire each
backend's ``register_backend(...)`` so that ``sealward probe`` lists all five
platforms and ``sealward.cli.get_backend(platform)`` resolves a live backend for
every supported :class:`~sealward.config_schema.Platform`.

The imports are plain (not optional-guarded): every backend module is written to
be importable on *every* OS — the platform-specific logic lives behind
``shutil.which`` / ``platform.system()`` runtime probes inside each backend, not
behind a platform-gated import. A failure to import any backend module is a real
wiring defect that must surface, not be swallowed.
"""

from __future__ import annotations

# Eager backend imports — each module self-registers via register_backend(...) at
# import time. These imports are the wiring that populates the CLI dispatch table
# for all five platforms. Order is alphabetical; registration is idempotent.
from sealward.backends import android as _android  # noqa: F401
from sealward.backends import ios as _ios  # noqa: F401
from sealward.backends import linux as _linux  # noqa: F401
from sealward.backends import macos as _macos  # noqa: F401
from sealward.backends import windows as _windows  # noqa: F401
from sealward.backends.base import CapabilityReport, SignerBackend, SignerBackendABC

__all__ = ["CapabilityReport", "SignerBackend", "SignerBackendABC"]
